## Week 5 - Parameter Variation and Algorithm Researching

- Symbol aligment is done by the blocks `Wifi Short Sync` + `Wifi Long Sync`. 
- In the first block we have that the signal is totally unknown
and because of this the metric that is used to determine if the signal being detected is in fact the target signal, we perform the autocorrelation, shifting the signal of the appropriate amount of time for the preamble sequence to go through.
- Having detected the start of the signal through this method we know have a complex task which consists in synchronizing the symbols. This is a very sensitive process and requires oms previsous knowledge of the signal, hence the Long Training Sequence which is standardized and known.
- This provides a way for precise timing resolution (or sample level accuracy) and also helps in the channel estimation
- The LTS block is implemented in the code:
```python
  # Conceptual implementation of matched filtering
  lts_sequence = known_64_sample_lts  # The standard LTS symbols
  correlation = signal * conj(lts_sequence)  # Complex multiplication
  filtered_output = fft(correlation)  # Frequency domain processing
  peak_index = argmax(abs(filtered_output))  # Find timing offset
```
---
### Why add 64 to the expression?
 $$n_\rho = \text{max}(N_\rho) +  64$$

- The value 64 is added to the expression 7 in order to skip the preamble sequence $N_\rho$.
- We have already introduced a delaty of 16 to skip the short training sequence and we add 64 for the LTS which spans 64 samples. 
- This whole sequence of 80 samples corresponds to the `cyclic prefix` composed of 16 samples from the STS plus 64 samples from the LTS.

---
### Testing 

- Analyzing the variation of the threshold and center frequency on the on the different file sources in `Wifi Baseband Recordings`.

- #### Test 1:
  - for this test the channel 100 source file was used
  - the signal was being viewd by  water and a frequency sink in the output of the long sync block
  - applying as a source the channel 100 (5.5GHz Center Frequency) I varied the center frequency from 5.180 GHz (low offset in my flowgraph) to 5.42GHz (high offset) while looking at the waterfal diagram and the channel (using a Frequency Sink), and observer that the transimission whas being detected in both cases.
  - next step was to make an extreme test, reducing the center frequency to the 2.44/2.38GHz and the result obtained was the same essentially. I still observerd the signal all the same with the periodic capture of a string signal in the waterfall and at the same seen in the frequency sink.
  - ## Puzzle #1

- #### Test 2
  - for this test the same sinks were used as in Test 1
  - the file source used changed to the channel 6 file source
  - the objective was to figure out if the parameters used with QT chooser blocks created were working or not by varying some parameters in the middle of the operation
  - as default center freqwuency is 5.18GHz I was immediately able to see that the signal wasa still bewing detected even tough it is in a channel that has a center frequency of 2.437GHz...

  - ## Puzzle #2

- ### Test 3
  - for this test the objective was to understand the impact of variation of the window size parameter which we expected a priori would affect the smoothing of the signal and the detection sensitivity from priori research about the FIR's
  - placed the sink @ the output of the Wifi Sync Short block 
---
### Playing with the methods in the gr-ieee-802.11 library

- Since testing the threshold parameters was not working I went in to the library code to look for the reason. In the code we determined that the threshold parameter in the `Sync Short block` was defined as:
```C++
const double d_threshold;
```
- therefore this parameter cannot be changed in runtime, that is why the QT GUI chooser did not actually apply the threshold value changed during runtime...
- Given this I went into the code to try to change this by adding a set_threshold method allowing me to change this value during runtime in GNU Radio
- For this i had to create the method (in the short sync class):
```C++
  class IEEE802_11_API sync_short : virtual public block {
    public:
      virtual void set_threshold(double threshold) = 0;
  }
```
- And add override option of this method in the sync_short_impl which inherits from the sync_short class:
```C++
  class sync_short_impl : public gr::ieee802_11::sync_short {
    public:
      void set_threshold(double threshold) override {
        d_threshold = threshold;
      }
  }
```
- After setting this variable `d_threshold` to non-constant:
```C++
  double d_threshold;
``` 
- In the end these changes did not work requiring more time invested in fixing this detail.
---
