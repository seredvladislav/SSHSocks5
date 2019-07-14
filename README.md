# SSHSocks5 (Development in progress)
based on code from https://github.com/fengyouchao/pysocks - source included as _socks5.py       
based on ideas from https://getssh.net/software          
python 2.7 code compatibility       
NOT heavy tested(!)
# How to:
pip install virtualenv      
cd your_project_dir     
virtualenv venv27       
Windows: call "venv27\\Scripts\activate"        
pip install -r requirements.txt     
# Run as   
python ssh_socks.py -ssh {ssh_host} -P {ssh_port} -l {ssh_user} -pw {ssh_password} -D {local_proxy_ip}:{local_proxy_port}     
Example:        
python ssh_socks.py -ssh 10.10.10.2 -P 22 -l cooluser -pw coolpassword -D 127.0.0.1:7000     
All other args will be ignored      
# Make exe on Windows:      
pip install -r dev-requirements.txt     
## pyinstaller:
pyinstaller ssh_socks.spec        
cd your_build_dir       
ssh_socks.exe -ssh 10.10.10.2 -P 22 -l cooluser -pw coolpassword -D 127.0.0.1:7000  
## py2exe 
python setup_py2exe.py      
cd your_build_dir   
ssh_socks.exe -ssh 10.10.10.2 -P 22 -l cooluser -pw coolpassword -D 127.0.0.1:7000       

       
