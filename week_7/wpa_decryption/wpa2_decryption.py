"""
WPA2 CCMP Decryption Block for GNU Radio

This block intercepts 802.11 frames, captures the 4-way handshake,
derives the PTK, and decrypts CCMP-encrypted data frames.

The decrypted frames are then forwarded to Wireshark with the
Protected bit cleared so they display as plaintext.

Usage:
  1. Set the correct SSID and password for your network
  2. The block will automatically capture the 4-way handshake
  3. Once keys are derived, encrypted frames will be decrypted
  4. Decrypted frames are sent to Wireshark via the output port

Note: You must capture the 4-way handshake (when a client connects)
for decryption to work. Force a reconnection if needed.
"""

import numpy as np
from gnuradio import gr
import pmt
import binascii
import hmac
import hashlib
import struct
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11QoS, Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


class wpa_decrypt_block(gr.sync_block):
    """
    WPA2-CCMP Decryption Block
    
    Captures the 4-way EAPOL handshake, derives encryption keys,
    and decrypts protected data frames in real-time.
    """
    
    def __init__(self, password="password", ssid="ssid"):
        gr.sync_block.__init__(
            self, 
            name="WPA2 Decryptor",
            in_sig=None,
            out_sig=None 
        )

        # Message Ports
        self.message_port_register_in(pmt.intern("in"))
        self.message_port_register_out(pmt.intern("out"))
        self.set_msg_handler(pmt.intern("in"), self.handle_msg)

        self.password = password
        self.ssid = ssid
        
        # Derive PMK from password and SSID (this is constant for a given network)
        print(f"[WPA2] Initializing for SSID: '{ssid}'")
        self.pmk = hashlib.pbkdf2_hmac(
            "sha1",
            self.password.encode("utf-8"),
            self.ssid.encode("utf-8"),
            4096,
            32
        )
        print(f"[WPA2] PMK: {binascii.hexlify(self.pmk).decode()[:20]}...")

        # Session state - can track multiple clients
        self.sessions = {}  # key: (ap_mac, client_mac) -> session_data
        
        # Stats
        self.frames_received = 0
        self.frames_decrypted = 0
        self.handshakes_captured = 0

    # ----------------------------------------------------------------
    # Key Derivation Functions
    # ----------------------------------------------------------------
    
    def prf_512(self, key, label, data):
        """
        IEEE 802.11i PRF-512 for PTK derivation.
        PRF-X(K, A, B) = HMAC-SHA1(K, A || 0x00 || B || i) for i = 0,1,2,...
        """
        result = b''
        # PRF-512 needs 64 bytes = 512 bits
        # SHA1 produces 20 bytes, so we need ceil(64/20) = 4 iterations
        for i in range(4):
            hmac_data = label.encode('ascii') + b'\x00' + data + bytes([i])
            result += hmac.new(key, hmac_data, hashlib.sha1).digest()
        return result[:64]  # Return first 512 bits (64 bytes)

    def derive_ptk(self, pmk, ap_mac, client_mac, anonce, snonce):
        """
        Derive PTK from PMK and handshake parameters.
        
        PTK = PRF-512(PMK, "Pairwise key expansion", 
                      min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
        
        PTK structure (64 bytes):
          - KCK (Key Confirmation Key): bytes 0-15 (for MIC)
          - KEK (Key Encryption Key): bytes 16-31 (for key wrapping)
          - TK (Temporal Key): bytes 32-47 (for CCMP encryption)
          - (remaining bytes unused for CCMP)
        """
        # Convert MAC addresses to bytes
        ap_bytes = binascii.unhexlify(ap_mac.replace(':', ''))
        client_bytes = binascii.unhexlify(client_mac.replace(':', ''))
        
        # Build the data: sorted MACs + sorted nonces
        if ap_bytes < client_bytes:
            mac_data = ap_bytes + client_bytes
        else:
            mac_data = client_bytes + ap_bytes
            
        if anonce < snonce:
            nonce_data = anonce + snonce
        else:
            nonce_data = snonce + anonce
        
        data = mac_data + nonce_data
        
        ptk = self.prf_512(pmk, "Pairwise key expansion", data)
        return ptk

    # ----------------------------------------------------------------
    # EAPOL Handshake Parsing
    # ----------------------------------------------------------------
    
    def parse_eapol_key(self, frame_bytes, scapy_pkt):
        """
        Parse EAPOL-Key frame to extract handshake information.
        
        EAPOL-Key frame structure (after 802.11 + LLC headers):
          - EAPOL Header (4 bytes): Version(1) + Type(1) + Length(2)
          - Key Descriptor Type (1 byte): 0x02 = RSN (WPA2)
          - Key Information (2 bytes): flags
          - Key Length (2 bytes)
          - Key Replay Counter (8 bytes)
          - Key Nonce (32 bytes)
          - Key IV (16 bytes)
          - Key RSC (8 bytes)
          - Key ID (8 bytes)
          - Key MIC (16 bytes)
          - Key Data Length (2 bytes)
          - Key Data (variable)
        """
        try:
            # Find EAPOL start - look for EAPOL signature after LLC
            # LLC/SNAP header: AA AA 03 00 00 00 88 8E
            llc_snap = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'
            
            idx = frame_bytes.find(llc_snap)
            if idx == -1:
                # Try without full SNAP
                idx = frame_bytes.find(b'\x88\x8e')
                if idx == -1:
                    return None
                eapol_start = idx + 2
            else:
                eapol_start = idx + 8
            
            eapol_data = frame_bytes[eapol_start:]
            
            if len(eapol_data) < 99:  # Minimum EAPOL-Key frame size
                return None
            
            # EAPOL Header
            eapol_version = eapol_data[0]
            eapol_type = eapol_data[1]
            eapol_length = struct.unpack('>H', eapol_data[2:4])[0]
            
            if eapol_type != 0x03:  # Not EAPOL-Key
                return None
            
            # Key Descriptor
            key_descriptor_type = eapol_data[4]
            if key_descriptor_type != 0x02:  # Not RSN (WPA2)
                print(f"[WPA2] Non-RSN key descriptor: {key_descriptor_type}")
                # Could be WPA1 (type 0xFE), continue anyway
            
            # Key Information (big-endian)
            key_info = struct.unpack('>H', eapol_data[5:7])[0]
            
            # Key Information bits (IEEE 802.11i):
            # Bit 0-2: Key Descriptor Version (1=HMAC-MD5/RC4, 2=HMAC-SHA1/AES)
            # Bit 3: Key Type (0=Group, 1=Pairwise)
            # Bit 4-5: Reserved
            # Bit 6: Install
            # Bit 7: Key Ack
            # Bit 8: Key MIC
            # Bit 9: Secure
            # Bit 10: Error
            # Bit 11: Request
            # Bit 12: Encrypted Key Data
            # Bit 13-15: Reserved
            
            key_type = (key_info >> 3) & 0x01      # Pairwise=1, Group=0
            key_install = (key_info >> 6) & 0x01
            key_ack = (key_info >> 7) & 0x01
            key_mic = (key_info >> 8) & 0x01
            key_secure = (key_info >> 9) & 0x01
            
            # Key Length
            key_length = struct.unpack('>H', eapol_data[7:9])[0]
            
            # Key Replay Counter (8 bytes at offset 9)
            replay_counter = eapol_data[9:17]
            
            # Key Nonce (32 bytes at offset 17)
            key_nonce = eapol_data[17:49]
            
            # Key MIC (16 bytes at offset 81)
            key_mic_value = eapol_data[81:97]
            
            return {
                'key_info': key_info,
                'key_type': key_type,
                'key_ack': key_ack,
                'key_mic': key_mic,
                'key_install': key_install,
                'key_secure': key_secure,
                'key_nonce': key_nonce,
                'replay_counter': replay_counter,
                'mic_value': key_mic_value
            }
            
        except Exception as e:
            print(f"[WPA2] EAPOL parse error: {e}")
            return None

    def get_session_key(self, ap_mac, client_mac):
        """Get or create session for AP-Client pair."""
        key = (ap_mac.lower(), client_mac.lower())
        if key not in self.sessions:
            self.sessions[key] = {
                'anonce': None,
                'snonce': None,
                'ptk': None,
                'tk': None,
                'handshake_state': 0
            }
        return self.sessions[key]

    def process_handshake(self, scapy_pkt, frame_bytes, eapol_info):
        """
        Process EAPOL handshake message and update session state.
        
        4-Way Handshake:
          M1: AP -> Client (ANonce, Ack=1, MIC=0)
          M2: Client -> AP (SNonce, Ack=0, MIC=1)
          M3: AP -> Client (ANonce, Ack=1, MIC=1, Install=1)
          M4: Client -> AP (Ack=0, MIC=1)
        """
        # Determine direction and extract MACs
        # In infrastructure mode:
        # To DS=0, From DS=1: AP -> Client (addr1=DA, addr2=BSSID, addr3=SA)
        # To DS=1, From DS=0: Client -> AP (addr1=BSSID, addr2=SA, addr3=DA)
        
        to_ds = scapy_pkt.FCfield.to_DS
        from_ds = scapy_pkt.FCfield.from_DS
        
        if from_ds and not to_ds:
            # From AP to Client
            ap_mac = scapy_pkt.addr2
            client_mac = scapy_pkt.addr1
            from_ap = True
        elif to_ds and not from_ds:
            # From Client to AP
            ap_mac = scapy_pkt.addr1
            client_mac = scapy_pkt.addr2
            from_ap = False
        else:
            # IBSS or WDS - not handled
            return
        
        session = self.get_session_key(ap_mac, client_mac)
        
        key_ack = eapol_info['key_ack']
        key_mic = eapol_info['key_mic']
        key_install = eapol_info['key_install']
        key_nonce = eapol_info['key_nonce']
        
        # Identify message type
        if key_ack and not key_mic:
            # Message 1: AP sends ANonce
            session['anonce'] = key_nonce
            session['handshake_state'] = 1
            print(f"[WPA2] M1: ANonce from AP {ap_mac}")
            
        elif not key_ack and key_mic and not key_install:
            # Message 2: Client sends SNonce
            if session['anonce'] is not None:
                session['snonce'] = key_nonce
                session['handshake_state'] = 2
                print(f"[WPA2] M2: SNonce from Client {client_mac}")
                
                # We now have enough to derive PTK!
                self.derive_session_keys(ap_mac, client_mac, session)
                
        elif key_ack and key_mic and key_install:
            # Message 3: AP confirms, sends GTK
            session['handshake_state'] = 3
            print(f"[WPA2] M3: Handshake confirmed by AP")
            
        elif not key_ack and key_mic and session['handshake_state'] >= 2:
            # Message 4: Client confirms
            session['handshake_state'] = 4
            self.handshakes_captured += 1
            print(f"[WPA2] M4: Handshake complete! Ready to decrypt.")

    def derive_session_keys(self, ap_mac, client_mac, session):
        """Derive PTK and TK for a session."""
        if session['anonce'] is None or session['snonce'] is None:
            return
        
        try:
            ptk = self.derive_ptk(
                self.pmk,
                ap_mac,
                client_mac,
                session['anonce'],
                session['snonce']
            )
            
            session['ptk'] = ptk
            session['tk'] = ptk[32:48]  # Temporal Key for CCMP
            
            print(f"[WPA2] *** Keys derived for {client_mac} ***")
            print(f"[WPA2]     TK: {binascii.hexlify(session['tk']).decode()}")
            
        except Exception as e:
            print(f"[WPA2] Key derivation error: {e}")

    # ----------------------------------------------------------------
    # CCMP Decryption
    # ----------------------------------------------------------------
    
    def decrypt_ccmp(self, scapy_pkt, frame_bytes, tk):
        """
        Decrypt a CCMP-protected frame.
        
        CCMP uses AES-CCM with:
          - 128-bit key (TK)
          - 13-byte nonce
          - 8-byte MIC (authentication tag)
        
        Frame structure:
          - MAC Header (24 or 30 bytes with QoS)
          - CCMP Header (8 bytes): PN0, PN1, Rsvd, KeyID|ExtIV, PN2-PN5
          - Encrypted Payload + MIC (8 bytes)
        """
        try:
            # Determine header length
            header_len = 24
            if scapy_pkt.haslayer(Dot11QoS):
                header_len = 26
            
            mac_header = frame_bytes[:header_len]
            ccmp_header = frame_bytes[header_len:header_len+8]
            encrypted_data = frame_bytes[header_len+8:]
            
            if len(encrypted_data) < 8:  # Need at least MIC
                return None
            
            # Extract Packet Number (PN) from CCMP header
            # PN is 48 bits: PN0, PN1, PN2, PN3, PN4, PN5 (little-endian)
            pn0 = ccmp_header[0]
            pn1 = ccmp_header[1]
            # ccmp_header[2] is reserved
            # ccmp_header[3] is KeyID (bits 6-7) and ExtIV flag (bit 5)
            pn2 = ccmp_header[4]
            pn3 = ccmp_header[5]
            pn4 = ccmp_header[6]
            pn5 = ccmp_header[7]
            
            # Build 6-byte PN (for nonce)
            pn = bytes([pn0, pn1, pn2, pn3, pn4, pn5])
            
            # Build Nonce (13 bytes)
            # Nonce = Priority (1) || A2 (6) || PN (6)
            # Priority: QoS TID if present, else 0
            if scapy_pkt.haslayer(Dot11QoS):
                priority = scapy_pkt[Dot11QoS].TID & 0x0f
            else:
                priority = 0
            
            a2 = binascii.unhexlify(scapy_pkt.addr2.replace(':', ''))
            nonce = bytes([priority]) + a2 + pn
            
            # Build AAD (Additional Authenticated Data)
            # AAD = FC(masked) || A1 || A2 || A3 || SC(masked) [|| A4] [|| QoS]
            aad = self.build_ccmp_aad(scapy_pkt, frame_bytes, header_len)
            
            # Decrypt using AES-CCM
            aes_ccm = AESCCM(tk, tag_length=8)
            
            # encrypted_data includes the 8-byte MIC at the end
            plaintext = aes_ccm.decrypt(nonce, encrypted_data, aad)
            
            return plaintext
            
        except Exception as e:
            # Decryption failures are common (wrong key, corrupted frame, etc.)
            # Only print occasionally to avoid spam
            if self.frames_received % 100 == 0:
                print(f"[WPA2] Decryption failed: {e}")
            return None

    def build_ccmp_aad(self, scapy_pkt, frame_bytes, header_len):
        """
        Build AAD for CCMP according to IEEE 802.11-2012.
        
        AAD includes the MAC header with certain fields masked:
          - FC: Subtype bits 4-6 masked, Retry/PwrMgt/MoreData/Order cleared
          - Sequence Control: Sequence number masked (keep fragment)
          - QoS: If present, bits 4-15 masked
        """
        # Get Frame Control (2 bytes, little-endian)
        fc = struct.unpack('<H', frame_bytes[0:2])[0]
        
        # Mask FC according to spec:
        # - Clear: Retry (bit 11), PwrMgt (bit 12), MoreData (bit 13), Order (bit 15)
        # - Keep: Protected (bit 14) set to 1
        # Mask = 0xC78F (clears bits 4-6, 11-13, 15, keeps bit 14)
        fc_masked = fc & 0x8f8f  # Clear subtype nibble bits and status bits
        fc_masked |= 0x4000  # Ensure Protected bit is set
        
        # Get addresses
        a1 = frame_bytes[4:10]
        a2 = frame_bytes[10:16]
        a3 = frame_bytes[16:22]
        
        # Sequence Control: mask sequence number (bits 4-15), keep fragment (bits 0-3)
        sc = struct.unpack('<H', frame_bytes[22:24])[0]
        sc_masked = sc & 0x000f
        
        # Build AAD
        aad = struct.pack('<H', fc_masked) + a1 + a2 + a3 + struct.pack('<H', sc_masked)
        
        # Add A4 if present (WDS mode: To DS=1 and From DS=1)
        to_ds = (fc >> 8) & 0x01
        from_ds = (fc >> 9) & 0x01
        if to_ds and from_ds:
            a4 = frame_bytes[24:30]
            aad += a4
        
        # Add QoS if present (masked)
        if scapy_pkt.haslayer(Dot11QoS):
            qos_offset = 24 if not (to_ds and from_ds) else 30
            qos = frame_bytes[qos_offset:qos_offset+2]
            qos_masked = bytes([qos[0] & 0x0f, 0x00])  # Mask bits 4-15
            aad += qos_masked
        
        return aad

    # ----------------------------------------------------------------
    # Message Handler
    # ----------------------------------------------------------------
    
    def handle_msg(self, msg):
        """Process incoming 802.11 frame PDU."""
        self.frames_received += 1
        
        # Extract frame data from PDU
        meta = pmt.car(msg)
        samples = pmt.cdr(msg)
        frame_bytes = bytes(pmt.u8vector_elements(samples))
        
        # Parse with Scapy
        try:
            scapy_pkt = Dot11(frame_bytes)
        except:
            self.message_port_pub(pmt.intern('out'), msg)
            return
        
        # Check for EAPOL handshake frames
        if scapy_pkt.haslayer(EAPOL):
            eapol_info = self.parse_eapol_key(frame_bytes, scapy_pkt)
            if eapol_info:
                self.process_handshake(scapy_pkt, frame_bytes, eapol_info)
            # Forward handshake frames unmodified
            self.message_port_pub(pmt.intern('out'), msg)
            return
        
        # Check for encrypted data frames
        # FC bit 14 = Protected Frame
        if len(frame_bytes) >= 2:
            fc = struct.unpack('<H', frame_bytes[0:2])[0]
            protected = (fc >> 14) & 0x01
            
            if protected:
                # Find session key for this frame
                tk = self.find_tk_for_frame(scapy_pkt)
                
                if tk:
                    plaintext = self.decrypt_ccmp(scapy_pkt, frame_bytes, tk)
                    
                    if plaintext:
                        self.frames_decrypted += 1
                        
                        # Build decrypted frame
                        decrypted_frame = self.build_decrypted_frame(
                            scapy_pkt, frame_bytes, plaintext
                        )
                        
                        if decrypted_frame:
                            # Send decrypted frame
                            out_data = pmt.init_u8vector(len(decrypted_frame), 
                                                          list(decrypted_frame))
                            new_msg = pmt.cons(meta, out_data)
                            self.message_port_pub(pmt.intern('out'), new_msg)
                            
                            if self.frames_decrypted % 10 == 1:
                                print(f"[WPA2] Decrypted {self.frames_decrypted} frames")
                            return
        
        # Forward original frame if not decrypted
        self.message_port_pub(pmt.intern('out'), msg)

    def find_tk_for_frame(self, scapy_pkt):
        """Find the TK for decrypting this frame based on addresses."""
        to_ds = scapy_pkt.FCfield.to_DS
        from_ds = scapy_pkt.FCfield.from_DS
        
        if from_ds and not to_ds:
            # From AP
            ap_mac = scapy_pkt.addr2
            client_mac = scapy_pkt.addr1
        elif to_ds and not from_ds:
            # To AP
            ap_mac = scapy_pkt.addr1
            client_mac = scapy_pkt.addr2
        else:
            return None
        
        key = (ap_mac.lower(), client_mac.lower())
        session = self.sessions.get(key)
        
        if session and session['tk']:
            return session['tk']
        
        return None

    def build_decrypted_frame(self, scapy_pkt, frame_bytes, plaintext):
        """
        Build a new frame with decrypted payload.
        
        - Remove CCMP header (8 bytes)
        - Remove MIC (already removed by decryption)
        - Clear Protected bit in FC
        """
        try:
            # Determine header length
            header_len = 24
            if scapy_pkt.haslayer(Dot11QoS):
                header_len = 26
            
            # Get MAC header
            mac_header = bytearray(frame_bytes[:header_len])
            
            # Clear Protected bit (bit 14 of FC, which is bit 6 of byte 1)
            mac_header[1] &= ~0x40
            
            # Combine header + plaintext (CCMP header removed, MIC removed)
            decrypted_frame = bytes(mac_header) + plaintext
            
            return decrypted_frame
            
        except Exception as e:
            print(f"[WPA2] Frame rebuild error: {e}")
            return None

    def get_stats(self):
        """Return current statistics."""
        return {
            'frames_received': self.frames_received,
            'frames_decrypted': self.frames_decrypted,
            'handshakes_captured': self.handshakes_captured,
            'active_sessions': len([s for s in self.sessions.values() if s['tk']])
        }


