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
from PyQt5 import QtCore
from PyQt5.QtCore import QObject, pyqtSlot
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



class main_proj_wifi_rx_week_7(gr.top_block, Qt.QWidget):

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

        self.settings = Qt.QSettings("gnuradio/flowgraphs", "main_proj_wifi_rx_week_7")

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
        self.user_threshold = user_threshold = 0.56
        self.update_period = update_period = 1
        self.samp_rate = samp_rate = 20000000
        self.delay = delay = 240
        self.chan_est = chan_est = 0
        self.center_frequency = center_frequency = 5180000000

        ##################################################
        # Blocks
        ##################################################

        self._user_threshold_range = qtgui.Range(0.56, 1.12, 0.01, 0.56, 200)
        self._user_threshold_win = qtgui.RangeWidget(self._user_threshold_range, self.set_user_threshold, "'user_threshold'", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._user_threshold_win)
        self._delay_range = qtgui.Range(240, 720, 20, 240, 200)
        self._delay_win = qtgui.RangeWidget(self._delay_range, self.set_delay, "'delay'", "counter_slider", int, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._delay_win)
        # Create the options list
        self._chan_est_options = [0, 1, 2, 3]
        # Create the labels list
        self._chan_est_labels = ['LS', 'LMS', 'Linear Comb', 'STA']
        # Create the combo box
        # Create the radio buttons
        self._chan_est_group_box = Qt.QGroupBox("'chan_est'" + ": ")
        self._chan_est_box = Qt.QHBoxLayout()
        class variable_chooser_button_group(Qt.QButtonGroup):
            def __init__(self, parent=None):
                Qt.QButtonGroup.__init__(self, parent)
            @pyqtSlot(int)
            def updateButtonChecked(self, button_id):
                self.button(button_id).setChecked(True)
        self._chan_est_button_group = variable_chooser_button_group()
        self._chan_est_group_box.setLayout(self._chan_est_box)
        for i, _label in enumerate(self._chan_est_labels):
            radio_button = Qt.QRadioButton(_label)
            self._chan_est_box.addWidget(radio_button)
            self._chan_est_button_group.addButton(radio_button, i)
        self._chan_est_callback = lambda i: Qt.QMetaObject.invokeMethod(self._chan_est_button_group, "updateButtonChecked", Qt.Q_ARG("int", self._chan_est_options.index(i)))
        self._chan_est_callback(self.chan_est)
        self._chan_est_button_group.buttonClicked[int].connect(
            lambda i: self.set_chan_est(self._chan_est_options[i]))
        self.top_layout.addWidget(self._chan_est_group_box)
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
        self.qtgui_sink_x_1 = qtgui.sink_c(
            1024, #fftsize
            window.WIN_BLACKMAN_hARRIS, #wintype
            center_frequency, #fc
            samp_rate, #bw
            "", #name
            True, #plotfreq
            True, #plotwaterfall
            True, #plottime
            True, #plotconst
            None # parent
        )
        self.qtgui_sink_x_1.set_update_time(1.0/10)
        self._qtgui_sink_x_1_win = sip.wrapinstance(self.qtgui_sink_x_1.qwidget(), Qt.QWidget)

        self.qtgui_sink_x_1.enable_rf_freq(True)

        self.top_layout.addWidget(self._qtgui_sink_x_1_win)
        self.iio_pluto_source_0 = iio.fmcomms2_source_fc32('' if '' else iio.get_pluto_uri(), [True, True], 32768)
        self.iio_pluto_source_0.set_len_tag_key('packet_len')
        self.iio_pluto_source_0.set_frequency(center_frequency)
        self.iio_pluto_source_0.set_samplerate(samp_rate)
        self.iio_pluto_source_0.set_gain_mode(0, 'manual')
        self.iio_pluto_source_0.set_gain(0, 20)
        self.iio_pluto_source_0.set_quadrature(True)
        self.iio_pluto_source_0.set_rfdc(True)
        self.iio_pluto_source_0.set_bbdc(True)
        self.iio_pluto_source_0.set_filter_params('Auto', '', 0, 0)
        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 2, True, False)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(delay, False, False)
        self.ieee802_11_parse_mac_0 = ieee802_11.parse_mac(True, True)
        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(ieee802_11.Equalizer(chan_est), center_frequency, 20e6, False, False)
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, False)
        self.foo_wireshark_connector_0 = foo.wireshark_connector(127, True)
        self.fir_filter_xxx_0_0 = filter.fir_filter_ccf(1, [1]*window_size)
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.fir_filter_xxx_0 = filter.fir_filter_fff(1, [1] * 64)
        self.fir_filter_xxx_0.declare_sample_delay(0)
        self.fft_vxx_1 = fft.fft_vcc(64, True, window.rectangular(64), True, 1)
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 64)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff((0.56/user_threshold))
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, '/tmp/wifi_pluto_week7.pcap', False)
        self.blocks_file_sink_0.set_unbuffered(True)
        self.blocks_divide_xx_0 = blocks.divide_ff(1)
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, delay)
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
        self.connect((self.blocks_divide_xx_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.ieee802_11_sync_short_0, 2))
        self.connect((self.blocks_multiply_xx_0, 0), (self.fir_filter_xxx_0_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_1, 0))
        self.connect((self.fft_vxx_1, 0), (self.ieee802_11_frame_equalizer_0, 0))
        self.connect((self.fir_filter_xxx_0, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.ieee802_11_sync_short_0, 1))
        self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.qtgui_sink_x_1, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_multiply_xx_0, 1))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("gnuradio/flowgraphs", "main_proj_wifi_rx_week_7")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_window_size(self):
        return self.window_size

    def set_window_size(self, window_size):
        self.window_size = window_size
        self.fir_filter_xxx_0_0.set_taps([1]*self.window_size)

    def get_user_threshold(self):
        return self.user_threshold

    def set_user_threshold(self, user_threshold):
        self.user_threshold = user_threshold
        self.blocks_multiply_const_vxx_0.set_k((0.56/self.user_threshold))

    def get_update_period(self):
        return self.update_period

    def set_update_period(self, update_period):
        self.update_period = update_period
        self._update_period_callback(self.update_period)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.iio_pluto_source_0.set_samplerate(self.samp_rate)
        self.qtgui_sink_x_1.set_frequency_range(self.center_frequency, self.samp_rate)

    def get_delay(self):
        return self.delay

    def set_delay(self, delay):
        self.delay = delay
        self.blocks_delay_0_0.set_dly(int(self.delay))

    def get_chan_est(self):
        return self.chan_est

    def set_chan_est(self, chan_est):
        self.chan_est = chan_est
        self._chan_est_callback(self.chan_est)
        self.ieee802_11_frame_equalizer_0.set_algorithm(ieee802_11.Equalizer(self.chan_est))

    def get_center_frequency(self):
        return self.center_frequency

    def set_center_frequency(self, center_frequency):
        self.center_frequency = center_frequency
        self._center_frequency_callback(self.center_frequency)
        self.ieee802_11_frame_equalizer_0.set_frequency(self.center_frequency)
        self.iio_pluto_source_0.set_frequency(self.center_frequency)
        self.qtgui_sink_x_1.set_frequency_range(self.center_frequency, self.samp_rate)




def main(top_block_cls=main_proj_wifi_rx_week_7, options=None):

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
