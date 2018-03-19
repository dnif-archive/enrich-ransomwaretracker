## Ransomware Tracker   
  https://ransomwaretracker.abuse.ch/blocklist/

### Overview
 Ransomware Tracker tracks and monitors the status of domain names, IP addresses and URLs that are associated with Ransomware,
 such as Botnet C&C servers, distribution sites and payment sites.
 By using data provided by Ransomware Tracker, hosting- and internet service provider (ISPs), as well as national CERTs/CSIRTs, law enforcement agencies (LEA) 
 and security researchers can receive an overview on infrastructure used by Ransomware and whether these are actively being used by miscreant to commit fraud.
 There are thre main category of the feeds provided

 Note
     The combined blocklists above are the recommended blocklists that should be used.
     They might not catch everything, but the false positive rate should be low. 
     However, false positives are possible, especially with regards to RW_IPBL. IP addresses associated with Ransomware Payment Sites (*_PS_IPBL) or 
     Locky botnet C&Cs (LY_C2_IPBL) stay listed on RW_IPBL for a time of 30 days after the last appearence.
     This means that an IP address stays listed on RW_IPBL even after the threat has been eliminated (e.g. the VPS / server has been suspended by the hosting provider) for another 30 days.

#### Ransomware Tracker Domain feeds  
 Master feed of known affected domain names.  
 This feed is merely an aggregate of the other feeds which list affected domain names . 
 The current list of malware families that are represented in these feeds are  
 
   | Blocklist    | Malware        | Scope  |
 |------------- |:-------------: |:-------------:|
 |CW_PS_DOMBL| CryptoWall      | Payment Sites	 |
 |TC_C2_DOMBL| TeslaCrypt      | Payment Sites      |
 |LY_C2_DOMBL| Locky | C2      |
 |LY_PS_DOMBL| Locky | Payment Sites	      |
 |TL_C2_DOMBL| TorrentLocker | C2 |
 |TL_PS_DOMBL| TorrentLocker | Payment Sites |
 |CB_PS_DOMBL| Cerber | Payment Sites	      |
 
 False Positive Score of this list is *LOW* 

#### Ransomware Tracker URL feeds
 Master feed of known affected URL
 This feed is merely an aggregate of the other feeds which list affected URL.
 The current list of malware families that are represented in these feeds are  
 
   | Blocklist    | Malware        | Scope  |
 |------------- |:-------------: |:-------------:|
 |CW_C2_URLBL| CryptoWall      | C2	 |
 |TC_C2_URLBL| TeslaCrypt      | C2  |
 |TC_DS_URLBL| TeslaCrypt | Distribution Sites	|
 |LY_DS_URLBL| Locky | Distribution Sites	|
 
 False Positive Score of this list is *LOW* 

#### Ransomware Tracker IP feeds
 Master feed of known affected IP
 This feed is merely an aggregate of the other feeds which list affected IP.
 The current list of malware families that are represented in these feeds are 
 
| Blocklist    | Malware        | Scope  |
 |------------- |:------------- |:-------------:|
 |TC_PS_IPBL| TeslaCrypt      | Payment Sites |
 |LY_C2_IPBL| Locky      | C2  |
 |TL_C2_IPBL| TorrentLocker | C2 |
 |TL_PS_IPBL| TorrentLocker | Payment Sites  |
 |CB_PS_IPBL| Cerber | Payment Sites      |
 
 False Positive Score of this list is *MEDIUM* 

### Using the Ransomware Tracker feeds API
 The Ransomware Tracker feeds API is found on github at

https://github.com/dnif/enrich-ransomwaretracker

#### Getting started with Ransomware Tracker feeds API

1. #####    Login to your Data Store, A10 containers  
   ACCESS DNIF CONTAINER VIA SSH : [Click To Know How](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/enrichment_plugin’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/enrichment_plugin/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/enrich-ransomwaretracker.git ransomwaretracker
```
### API feed output structure
| Fields        | Description  |
| ------------- |:-------------:|
| EvtType      | An IP/Domain/URL |
| EvtName      | The IOC      |
| IntelRef | Feed Name      |
| IntelRefURL | Feed URL      |
| ThreatType | DNIF Feed Identification Name |      

An example of API feed output
```
{'EvtType': 'DOMAIN', 
'EvtName': 'pmenboeqhyrpvomq.shutlazy.casa', 
'AddFields': {
'IntelRef': ['RANSOMWARETRACKER'],
'IntelRefURL': ['https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'], 
'ThreatType': ['malware'] 
}}
```
