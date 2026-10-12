# 1. Clone
cd ~ && rm -rf Sentinel
git clone https://github.com/redline1736/Sentinel.git
cd Sentinel

# 4. Build
make clean all

# 5. Install
sudo install -m 0755 sentinel /usr/bin/sentinel
sudo mkdir -p /usr/share/sentinel
sudo cp -r ghostquery /usr/share/sentinel/

# 6. Run
cd /tmp
sentinel -h

# If it can't find payloads from /tmp, apply the payload_path() patch from Step 7.