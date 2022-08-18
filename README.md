# MiningPerturbation
MiningPerturbation is a packet manipulation network perturbation python script for bypassing the network-based cryptojacking detection model (Tekiner et al. ).

## Requirement
- tsfresh
- scapy
- bettercap
- scikit-learn
- pandas
- numpy

## Target ML Model
Tekiner et al. [1] recently proposed the state-of-the-art cryptojacking detection system in IoT networks, using the IoT devices’ network traffic for cryptojacking. The proposed solution first extracts time-series features from network packet data between an IoT device and a mining server (by the tsfresh [2] package in Python) and analyzes their statistical properties to use them as the features for a classifier. Tekiner et al. performed experiments to find the key features, the most accurate classifier, and the optimum training size and evaluated the effectiveness of their cryptojacking detection mechanisms under various attacker configurations and network
conditions. The experimental results showed that the best classifier achieved 97% detection accuracy with only one hour of training data.

## Perturbations for adversarial examples
- **Dummy packet** s to randomly insert a dummy packet into the network packets for crypto mining at 𝑡 time interval.
- **Padding** adds 𝑘 zero bytes at the end of a chosen packet to adjust its size and updates the packet length and checksum fields after padding.
- **Splitting** is to break a packet into several smaller packets. Given a sequence of packets for either TCP or UDP traffic, an attacker assembles the packets and then splits them into 𝑘 packets again.
- **Obfuscation proxy** is to use a network proxy server obfuscating the distribution of packet sizes and timing among packets. Check out obfs4 (https://github.com/Yawning/obfs4) which is used in our experiment

## Contact
If you experience any issues, you can ask for help by contacting us at kiho@skku.edu

## References
[1] Ege Tekiner, Abbas Acar, and A Selcuk Uluagac. A Lightweight IoT Cryptojacking Detection Mechanism in Heterogeneous Smart Home Networks. In Proc. of the ISOC Network and Distributed System Security Symposium (NDSS), 2022.

[2] Maximilian Christ, Nils Braun, Julius Neuffer, and Andreas W Kempa-Liehr. Time Series FeatuRe Extraction on basis of Scalable Hypothesis tests (tsfresh – A Python package). Neurocomputing, 2018. (https://github.com/blue-yonder/tsfresh)
