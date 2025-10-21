#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# GNU Radio version: 3.10.12.0

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio import blocks
from gnuradio import fft
from gnuradio.fft import window
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
import sys
import signal
from PyQt5 import Qt
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import iio
import foo
import ieee802_11
import sip
import threading



class main_proj_wifi_rx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Not titled yet")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except BaseException as exc:
            print(f"Qt GUI: Could not set Icon: {str(exc)}", file=sys.stderr)
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("gnuradio/flowgraphs", "main_proj_wifi_rx")

        try:
            geometry = self.settings.value("geometry")
            if geometry:
                self.restoreGeometry(geometry)
        except BaseException as exc:
            print(f"Qt GUI: Could not restore geometry: {str(exc)}", file=sys.stderr)
        self.flowgraph_started = threading.Event()

        ##################################################
        # Variables
        ##################################################
        self.window_size = window_size = 64
        self.samp_rate = samp_rate = 20000000

        ##################################################
        # Blocks
        ##################################################

        self.qtgui_sink_x_0 = qtgui.sink_f(
            1024, #fftsize
            window.WIN_BLACKMAN_hARRIS, #wintype
            5600000000, #fc
            samp_rate, #bw
            "Freq/Waterfall/TimeDomain/Const", #name
            True, #plotfreq
            True, #plotwaterfall
            True, #plottime
            True, #plotconst
            None # parent
        )
        self.qtgui_sink_x_0.set_update_time(1.0/10)
        self._qtgui_sink_x_0_win = sip.wrapinstance(self.qtgui_sink_x_0.qwidget(), Qt.QWidget)

        self.qtgui_sink_x_0.enable_rf_freq(False)

        self.top_layout.addWidget(self._qtgui_sink_x_0_win)
        self.iio_pluto_source_0 = iio.fmcomms2_source_fc32('' if '' else iio.get_pluto_uri(), [True, True], 32768)
        self.iio_pluto_source_0.set_len_tag_key('packet_len')
        self.iio_pluto_source_0.set_frequency(5890000000)
        self.iio_pluto_source_0.set_samplerate(samp_rate)
        self.iio_pluto_source_0.set_gain_mode(0, 'manual')
        self.iio_pluto_source_0.set_gain(0, 10)
        self.iio_pluto_source_0.set_quadrature(True)
        self.iio_pluto_source_0.set_rfdc(True)
        self.iio_pluto_source_0.set_bbdc(True)
        self.iio_pluto_source_0.set_filter_params('Auto', '', 0, 0)
        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 2, False, False)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(240, False, False)
        self.ieee802_11_parse_mac_0 = ieee802_11.parse_mac(True, False)
        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(ieee802_11.LS, 5.6e9, 20e6, False, False)
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, False)
        self.foo_wireshark_connector_0 = foo.wireshark_connector(127, False)
        self.fir_filter_xxx_0_0 = filter.fir_filter_ccc(1, [1]*window_size)
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.fir_filter_xxx_0 = filter.fir_filter_fff(1, [1] * window_size)
        self.fir_filter_xxx_0.declare_sample_delay(0)
        self.fft_vxx_0 = fft.fft_vcc(window_size, True, window.blackmanharris(64), True, 1)
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 64)
        self.blocks_null_sink_0 = blocks.null_sink(gr.sizeof_char*1)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_divide_xx_0 = blocks.divide_ff(1)
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, 240)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, 16)
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_complex_to_mag_0 = blocks.complex_to_mag(1)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ieee802_11_decode_mac_0, 'out'), (self.ieee802_11_parse_mac_0, 'in'))
        self.msg_connect((self.ieee802_11_parse_mac_0, 'out'), (self.foo_wireshark_connector_0, 'in'))
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_divide_xx_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.fir_filter_xxx_0, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.blocks_conjugate_cc_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_short_0, 0))
        self.connect((self.blocks_delay_0_0, 0), (self.ieee802_11_sync_long_0, 1))
        self.connect((self.blocks_divide_xx_0, 0), (self.ieee802_11_sync_short_0, 2))
        self.connect((self.blocks_divide_xx_0, 0), (self.qtgui_sink_x_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.fir_filter_xxx_0_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.ieee802_11_frame_equalizer_0, 0))
        self.connect((self.fir_filter_xxx_0, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.ieee802_11_sync_short_0, 1))
        self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_null_sink_0, 0))
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_multiply_xx_0, 1))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("gnuradio/flowgraphs", "main_proj_wifi_rx")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_window_size(self):
        return self.window_size

    def set_window_size(self, window_size):
        self.window_size = window_size
        self.fir_filter_xxx_0.set_taps([1] * self.window_size)
        self.fir_filter_xxx_0_0.set_taps([1]*self.window_size)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.iio_pluto_source_0.set_samplerate(self.samp_rate)
        self.qtgui_sink_x_0.set_frequency_range(5600000000, self.samp_rate)




def main(top_block_cls=main_proj_wifi_rx, options=None):

    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()

    tb.start()
    tb.flowgraph_started.set()

    tb.show()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    qapp.exec_()

if __name__ == '__main__':
    main()
