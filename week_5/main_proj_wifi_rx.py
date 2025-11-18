#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Wifi RX SDR
# GNU Radio version: 3.10.12.0

from PyQt5 import Qt
from gnuradio import qtgui
from PyQt5 import Qt
import sip
from gnuradio import fosphor
from gnuradio.fft import window
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import blocks
import pmt
from gnuradio import fft
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import network
import foo
import ieee802_11
import threading



class main_proj_wifi_rx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Wifi RX SDR", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Wifi RX SDR")
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
        self.window_size = window_size = 48
        self.update_period = update_period = 1
        self.samp_rate = samp_rate = 20000000
        self.center_frequency = center_frequency = 5180000000

        ##################################################
        # Blocks
        ##################################################

        # Create the options list
        self._window_size_options = [16, 32, 48, 64, 96]
        # Create the labels list
        self._window_size_labels = ['16', '32', '48', '64', '96']
        # Create the combo box
        self._window_size_tool_bar = Qt.QToolBar(self)
        self._window_size_tool_bar.addWidget(Qt.QLabel("window_size" + ": "))
        self._window_size_combo_box = Qt.QComboBox()
        self._window_size_tool_bar.addWidget(self._window_size_combo_box)
        for _label in self._window_size_labels: self._window_size_combo_box.addItem(_label)
        self._window_size_callback = lambda i: Qt.QMetaObject.invokeMethod(self._window_size_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._window_size_options.index(i)))
        self._window_size_callback(self.window_size)
        self._window_size_combo_box.currentIndexChanged.connect(
            lambda i: self.set_window_size(self._window_size_options[i]))
        # Create the radio buttons
        self.top_layout.addWidget(self._window_size_tool_bar)
        # Create the options list
        self._center_frequency_options = [5220000000, 5180000000, 2420000000, 2380000000]
        # Create the labels list
        self._center_frequency_labels = ['5G high offset', '5G low offset', '2.4G high offset', '2.4G low offset']
        # Create the combo box
        self._center_frequency_tool_bar = Qt.QToolBar(self)
        self._center_frequency_tool_bar.addWidget(Qt.QLabel("'center_frequency'" + ": "))
        self._center_frequency_combo_box = Qt.QComboBox()
        self._center_frequency_tool_bar.addWidget(self._center_frequency_combo_box)
        for _label in self._center_frequency_labels: self._center_frequency_combo_box.addItem(_label)
        self._center_frequency_callback = lambda i: Qt.QMetaObject.invokeMethod(self._center_frequency_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._center_frequency_options.index(i)))
        self._center_frequency_callback(self.center_frequency)
        self._center_frequency_combo_box.currentIndexChanged.connect(
            lambda i: self.set_center_frequency(self._center_frequency_options[i]))
        # Create the radio buttons
        self.top_layout.addWidget(self._center_frequency_tool_bar)
        # Create the options list
        self._update_period_options = [0.001, 0.01, 1, 5, 10]
        # Create the labels list
        self._update_period_labels = ['1ms', '10ms', '1s', '5s', '10s']
        # Create the combo box
        self._update_period_tool_bar = Qt.QToolBar(self)
        self._update_period_tool_bar.addWidget(Qt.QLabel("'update_period'" + ": "))
        self._update_period_combo_box = Qt.QComboBox()
        self._update_period_tool_bar.addWidget(self._update_period_combo_box)
        for _label in self._update_period_labels: self._update_period_combo_box.addItem(_label)
        self._update_period_callback = lambda i: Qt.QMetaObject.invokeMethod(self._update_period_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._update_period_options.index(i)))
        self._update_period_callback(self.update_period)
        self._update_period_combo_box.currentIndexChanged.connect(
            lambda i: self.set_update_period(self._update_period_options[i]))
        # Create the radio buttons
        self.top_layout.addWidget(self._update_period_tool_bar)
        self.network_socket_pdu_0 = network.socket_pdu('UDP_CLIENT', '127.0.0.1', '52001', 1500, False)
        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.8, 2, True, True)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(240, False, False)
        self.ieee802_11_parse_mac_0 = ieee802_11.parse_mac(True, False)
        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(ieee802_11.LS, center_frequency, 20e6, False, False)
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, False)
        self.fosphor_qt_sink_c_0 = fosphor.qt_sink_c()
        self.fosphor_qt_sink_c_0.set_fft_window(window.WIN_BLACKMAN_hARRIS)
        self.fosphor_qt_sink_c_0.set_frequency_range(center_frequency, samp_rate)
        self._fosphor_qt_sink_c_0_win = sip.wrapinstance(self.fosphor_qt_sink_c_0.pyqwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._fosphor_qt_sink_c_0_win)
        self.foo_wireshark_connector_0 = foo.wireshark_connector(127, True)
        self.fir_filter_xxx_0_0 = filter.fir_filter_ccf(1, [1]*window_size)
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.fir_filter_xxx_0 = filter.fir_filter_fff(1, [1] * window_size)
        self.fir_filter_xxx_0.declare_sample_delay(0)
        self.fft_vxx_1 = fft.fft_vcc(64, True, window.rectangular(64), True, 1)
        self.blocks_throttle2_0 = blocks.throttle( gr.sizeof_gr_complex*1, samp_rate, True, 0 if "auto" == "auto" else max( int(float(0.1) * samp_rate) if "auto" == "time" else int(0.1), 1) )
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 64)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_file_source_1 = blocks.file_source(gr.sizeof_gr_complex*1, '/home/guilherme/Desktop/MEEC/DigitalCommunications/MainProject/Wifi_Project_Baseband_recordings/Sample2_20MHz_Channel6.bin', True, 0, 0)
        self.blocks_file_source_1.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, '/home/guilherme/Desktop/MEEC/DigitalCommunications/MainProject/week_3/my_recording_pluto.pcap', True)
        self.blocks_file_sink_0.set_unbuffered(True)
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
        self.msg_connect((self.ieee802_11_parse_mac_0, 'out'), (self.network_socket_pdu_0, 'pdus'))
        self.msg_connect((self.network_socket_pdu_0, 'pdus'), (self.foo_wireshark_connector_0, 'in'))
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_divide_xx_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.fir_filter_xxx_0, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.blocks_conjugate_cc_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_short_0, 0))
        self.connect((self.blocks_delay_0_0, 0), (self.ieee802_11_sync_long_0, 1))
        self.connect((self.blocks_divide_xx_0, 0), (self.ieee802_11_sync_short_0, 2))
        self.connect((self.blocks_file_source_1, 0), (self.blocks_throttle2_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.fir_filter_xxx_0_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_1, 0))
        self.connect((self.blocks_throttle2_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.blocks_throttle2_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.blocks_throttle2_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.fft_vxx_1, 0), (self.ieee802_11_frame_equalizer_0, 0))
        self.connect((self.fir_filter_xxx_0, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.ieee802_11_sync_short_0, 1))
        self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.fosphor_qt_sink_c_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))


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
        self._window_size_callback(self.window_size)
        self.fir_filter_xxx_0.set_taps([1] * self.window_size)
        self.fir_filter_xxx_0_0.set_taps([1]*self.window_size)

    def get_update_period(self):
        return self.update_period

    def set_update_period(self, update_period):
        self.update_period = update_period
        self._update_period_callback(self.update_period)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_throttle2_0.set_sample_rate(self.samp_rate)
        self.fosphor_qt_sink_c_0.set_frequency_range(self.center_frequency, self.samp_rate)

    def get_center_frequency(self):
        return self.center_frequency

    def set_center_frequency(self, center_frequency):
        self.center_frequency = center_frequency
        self._center_frequency_callback(self.center_frequency)
        self.fosphor_qt_sink_c_0.set_frequency_range(self.center_frequency, self.samp_rate)
        self.ieee802_11_frame_equalizer_0.set_frequency(self.center_frequency)




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
