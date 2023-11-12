---
title: "Pattern Recognition Resonators"
date: 2023-11-10T13:55:54+01:00
draft: false
author: Eric Armbruster
tags: 
- resonate-and-fire-neuron
- pattern-recognition
- neural-networks
- SNN
- hebbian-learning
categories:
- Data-Science
---

# Pattern Recognition Resonators

This project demonstrates Resonate-and-Fire (RF) neurons and unsupervised hebbian learning can be combined to build Spiking Neural Networks (SNNs) that are capable of recognizing (complex) patterns in time data.

## Results

We have no proper evaluation comparing against other state-of-the-art networks yet, as this code was created during a neuromorphic hackathon organized by [neurotum](https://www.neurotum.com/) x [Fortiss](https://www.fortiss.org/). 
The hyperparameters, input data and output data of the experimental networks are saved in [save](./save).

**Proof-of-Concept on SOS:**

We encoded an SOS signal and fed it into the below visualized network. 
The animation shows the second neuron on the fourth layer blinking every time the SOS signal is fully received.

For each layer we need to specify a range of frequencies the RF neuron selects. This explains why only some neurons are propagating the signal in certain layers, as only these neurons match the frequency of the input signal closely enough. Experimental results showed this to be working well for frequencies that are in the range of +-2Hz of the input spike. 

We have also visualized the two neurons in the fourth layer in a line chart, which shows when they spike:

![sos2](/images/resonators/Train_SNN_output.gif)

![train_layer4neuron2real_imag_and_spikes](/images/resonators/Train.png)

The network recognizes this specific signal, but ignores other signals such as the one we sent in the animation below:

![sos2](/images/resonators/Test_SNN_output.gif)

The line chart shows for this input the neurons on the fourth layer never spiked:

![test_layer4neuron2real_imag_and_spikes](/images/resonators/Test.png)


## Credits

Credits for this work go to:

- Borislav Polovnikov
- Thomas Huber
- Eric Armbruster
- Reem Al Fata
- Jules Lecomte

Thank you Reem and Jules for supervising us during this hackathon and providing us with such an amazing topic!

Thank you also to the whole neuromorphic [Fortiss](https://www.fortiss.org/) research team and to [neurotum](https://www.neurotum.com/) for providing us with this amazing opportunity to work on cutting-edge research topic, organizing, and preparing the hackathon!
