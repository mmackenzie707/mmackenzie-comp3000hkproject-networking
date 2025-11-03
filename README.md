sudo apt install python3-venv iptables
git clone https://github.com/you/smartfw.git
cd smartfw
python3 -m venv venv && source venv/bin/activate
pip install -e .
sudo python -m smartfw   # or simply `sudo smartfw`