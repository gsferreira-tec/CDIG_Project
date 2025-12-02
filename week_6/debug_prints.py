#!/usr/bin/env python3
# A small GNU Radio message-based helper block to print SSIDs received from
# ieee802_11.parse_mac PDUs. It can be instantiated and connected to the
# 'out' message port of `parse_mac` in a flowgraph.

from gnuradio import gr
import pmt
import time


class DebugPrints(gr.basic_block):
    """Message-based GNURadio block that prints SSIDs (if present) from PDUs.

    Usage:
    1) Instantiate the block and add it to the top_block instance:
       debug = DebugPrints()
       tb.msg_connect((tb.ieee802_11_parse_mac_0, 'out'), (debug, 'in'))

    2) Start the flowgraph. The block prints SSIDs as they are seen.
    """

    def __init__(self, unique=True, print_all=False):
        gr.basic_block.__init__(self,
                                name="debug_prints",
                                in_sig=None,
                                out_sig=None)

        # message port IO
        self.message_port_register_in(pmt.intern('in'))
        self.set_msg_handler(pmt.intern('in'), self.handle_pdu)

        # settings
        self.print_all = print_all
        self.unique = unique
        self._seen_ssids = set()

    def handle_pdu(self, msg):
        # msg is a PMT pair (meta, pdu)
        if pmt.is_eof_object(msg):
            return
        if not pmt.is_pair(msg):
            return

        meta = pmt.car(msg)
        pdu = pmt.cdr(msg)

        # Try to find 'ssid' in metadata
        ssid_key = pmt.intern('ssid')
        if pmt.is_dict(meta) and pmt.dict_has_key(meta, ssid_key):
            # pmt.dict_ref in this environment expects a default 'not_found' value
            val = pmt.dict_ref(meta, ssid_key, pmt.PMT_NIL)
            # convert to Python string safely
            try:
                # pmt.to_python converts to native types
                ssid_py = pmt.to_python(val)
            except Exception:
                try:
                    ssid_py = pmt.symbol_to_string(val)
                except Exception:
                    ssid_py = str(val)

            if ssid_py is None:
                return
            # skip empty SSID (hidden networks)
            if isinstance(ssid_py, str) and ssid_py.strip() == '':
                return

            # If unique mode, print a new SSID only when its first seen
            if self.unique and ssid_py in self._seen_ssids and not self.print_all:
                return

            self._seen_ssids.add(ssid_py)
            print(f"[debug_prints] SSID: {ssid_py}")


# Utility to attach this block to the main flowgraph
def attach_to_flowgraph(tb, unique=True, print_all=False):
    """Create a DebugPrints instance, attach it to top block `tb`'s parse_mac 'out'.

    Returns the debug block instance (so you can keep a reference if you want).
    """
    dbg = DebugPrints(unique=unique, print_all=print_all)
    # add to the top_block object so it can be referenced and GC not collected
    tb.debug_prints_0 = dbg
    try:
        tb.msg_connect((tb.ieee802_11_parse_mac_0, 'out'), (dbg, 'in'))
    except Exception as e:
        # If msg_connect fails (e.g. port naming or missing block), raise
        print(f"[debug_prints] attach failed: {e}")
        raise
    return dbg


if __name__ == '__main__':
    # Minimal demo: import flowgraph from week_6 and attach the debug block
    # This script expects to run from the workspace root (CDIG_Project/) so it
    # can import the generated Python flowgraph file.
    import importlib.util
    import os

    fg_path = os.path.abspath('week_6/main_proj_wifi_rx_week_6.py')
    spec = importlib.util.spec_from_file_location('main_top', fg_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    tb = mod.main_proj_wifi_rx()
    dbg = attach_to_flowgraph(tb)

    tb.start()
    tb.flowgraph_started.set()
    tb.show()

    try:
        # Keep the script alive until user exits GUI
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tb.stop()
        tb.wait()
        print('Stopped.')
