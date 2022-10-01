# Python_for_security
This repo contains security related projects implemented in python. Should be used for learning and educational purpose only.

This repo contains python scripts for :

* PySecureStore: Securely storing all passwords and access using trusted store.
* Detect_ssh_and_ftp_Brute : Python script for detecting a potential SSH or FTP brute force attack using heurestics and flow analysis.
* Feature Selection for analysing traffic.

* PySecureStore is a simple tool which parses your file with all your passwords and encrypts them and stores them in Keychain app. The file is deleted imeediately afterwards. Also, the passwords stored in google chrome can be fetched and used here instead of files (working on it). All passwords are stored in Secure system trust store like keychain and can only be derived with one key phrase which is passed dynamically.

Future Idea : For each authentication event trigger creation of a key and use it to encrypt passwords.

To run PySecureStore : 
python3 SecurePasswordStorage/password_store.py --filepath "pwd_file_name" --key <a_long_alphanumeric_string> --keyid <ID>  
