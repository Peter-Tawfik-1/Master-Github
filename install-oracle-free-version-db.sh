sudo yum update -y #save time for first run
sudo yum install wget -y
sudo mkdir sw
sudo mkdir log
sudo chmod 777 sw
sudo chmod 777 log
cd sw
wget https://yum.oracle.com/repo/OracleLinux/OL9/appstream/x86_64/getPackage/oracle-database-preinstall-23ai-1.0-2.el9.x86_64.rpm
wget https://download.oracle.com/otn-pub/otn_software/db-free/oracle-database-free-23ai-1.0-1.el9.x86_64.rpm
sudo dnf -y install oracle-database-preinstall-23ai-1.0-2.el9.x86_64.rpm > /home/peter/log/install_log.txt
sudo dnf install -y oracle-database-free* >> /home/peter/log/install_log.txt
#Note : I am creating sys password as sys to make the DB vulnarable for testing but from the GCP firewall it's not accissable.
#export DB_PASSWORD=sys
(echo sys; echo sys;) | sudo /etc/init.d/oracle-free-23ai configure >> /home/peter/log/config_log.txt


# In oralce profile follow https://docs.oracle.com/en/database/oracle/oracle-database/23/xeinl/installing-oracle-database-free.html#GUID-A5FCC804-5786-4B4B-B1B4-60E36E80B73F
Sudo su - oracle
export ORACLE_SID=FREE 
export ORAENV_ASK=NO 
. /opt/oracle/product/23ai/dbhomeFree/bin/oraenv


#sudo vi /etc/ssh/sshd_config
#PasswordAuthentication yes
#sudo service sshd restart
ClientAliveInterval  1200
ClientAliveCountMax 3