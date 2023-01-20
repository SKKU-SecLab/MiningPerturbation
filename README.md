# Poster: Adversarial Perturbation Attacks on the State-of-the-Art Cryptojacking Detection System in IoT Networks (ACM CCS 2022)

#### Kiho Lee*, Sanghak Oh*, and Hyoungshick Kim*.
##### Sungkyunkwan University*

---

## MiningPerturbation

MiningPerturbation is a python script for bypassing the network-based cryptojacking detection model (Tekiner et al. ) using network packet manipulation.

## Target Machine Learning Model
Tekiner et al. [1] recently proposed the state-of-the-art cryptojacking detection system in IoT networks, using the IoT devices’ network traffic for cryptojacking. The proposed solution first extracts time-series features from network packet data between an IoT device and a mining server (by the tsfresh [2] package in Python) and analyzes their statistical properties to use them as the features for a classifier. Tekiner et al. performed experiments to find the key features, the most accurate classifier, and the optimum training size and evaluated the effectiveness of their cryptojacking detection mechanisms under various attacker configurations and network
conditions. The experimental results showed that the best classifier achieved 97% detection accuracy with only one hour of training data.

## Perturbations for adversarial examples
- **Dummy packet** s to randomly insert a dummy packet into the network packets for crypto mining at 𝑡 time interval.
- **Padding** adds 𝑘 zero bytes at the end of a chosen packet to adjust its size and updates the packet length and checksum fields after padding.
- **Splitting** is to break a packet into several smaller packets. Given a sequence of packets for either TCP or UDP traffic, an attacker assembles the packets and then splits them into 𝑘 packets again.
- **Obfuscation proxy** is to use a network proxy server obfuscating the distribution of packet sizes and timing among packets. Check out obfs4 (https://github.com/Yawning/obfs4) which is used in our experiment

## Experimental environment
- Linux kali 5.18.0-kali5-amd64
- python 3.10.5

## Requirement
We recommand using the python3-venv environment.
```bash
!sudo apt-get install python3-venv
!python3 -m venv <env_name>
!source <env_name>/bin/activate
!cd <env_name>
!pip install tsfresh scapy scikit-learn pandas numpy
```
## Usage
```bash
python MiningPerturbation_sock.py <LOCAL_HOST> <LOCAL_PORT> <REMOTE_HOST> <REMOTE_PORT> <RECEIVE_FIRST:TRUE>

# For clearing the perturbation procss
sudo kill -9 `ps -ef | grep MiningPerturbation | grep -v grep | awk '{print $2}'`
```
  ### Example (gulf.moneroocean.stream:10128)
  - Execute MiningPerturbation terminal first.
  ```bash
  sudo python MiningPerturbation_sock.py 192.168.126.129 10128 gulf.moneroocean.stream 10128 True
  ```
  ![image](https://user-images.githubusercontent.com/47383452/186924229-b3f4dc08-e676-4188-875f-2f1b88260f76.png)
  
  - In another terminal, xmrig console
  ```bash
  /xmrig -o <LOCAL_HOST>:<LOCAL_PORT> -u <XMRIG_WALLET> -p pi3bplus -t 4 -l mining_crypto_xmr_xmrig.log
  ```

## See Results
The result of the attack can be checked in the following file. 
- (https://github.com/SKKU-SecLab/MiningPerturbation/blob/main/Adversarial_Perturbation_Results.ipynb)
```bash
git clone https://github.com/SKKU-SecLab/MiningPerturbation.git
cd MiningPerturbation
```
Open the file "Adversarial_Perturbation_Results.ipynb" and then try to run it.

## Contact
If you experience any issues, you can ask for help by contacting us at kiho@skku.edu

## References
[1] Ege Tekiner, Abbas Acar, and A Selcuk Uluagac. A Lightweight IoT Cryptojacking Detection Mechanism in Heterogeneous Smart Home Networks. In Proc. of the ISOC Network and Distributed System Security Symposium (NDSS), 2022.

[2] Maximilian Christ, Nils Braun, Julius Neuffer, and Andreas W Kempa-Liehr. Time Series FeatuRe Extraction on basis of Scalable Hypothesis tests (tsfresh – A Python package). Neurocomputing, 2018. (https://github.com/blue-yonder/tsfresh)



## Citation
```bibtex
@inproceedings{lee2022adversarial,
  title={Adversarial Perturbation Attacks on the State-of-the-Art Cryptojacking Detection System in IoT Networks},
  author={Lee, Kiho and Oh, Sanghak and Kim, Hyoungshick},
  booktitle={Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security},
  year={2022}
}
```
