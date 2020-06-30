#!/bin/bash


#Import the Elastic stack PGP repository signing Key

sudo wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch --no-check-certificate | sudo apt-key add - &&\

#install Elasicsearch;

echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list &&\

#Update package cache and install Elasticsearch;

apt update &&\

apt install elasticsearch &&\

#EC2 Discovery plug for AWS

sudo bin/elasticsearch-plugin install discovery-ec2 &&\

#configure Elastic Search

sudo bash -c 'echo cluster.name : ELK-Server >> /etc/elasticsearch/elasticsearch.yml' &&\

sudo bash -c 'echo network.host: IP.OF.SERVER.ELK >> /etc/elasticsearch/elasticsearch.yml' &&\

sudo bash -c 'echo http.port: 9200 >> /etc/elasticsearch/elasticsearch.yml' &&\

sudo bash -c 'echo discovery.type: single-node >> /etc/elasticsearch/elasticsearch.yml' &&\

#configure JVM heap size

sudo bash -c 'echo -Xms512m >> /etc/elasticsearch/jvm.options' &&\

#Running Elasticseach

systemctl enable --now elasticsearch &&\


#Install Kibana

apt install kibana &&\

#open port 5601 for Kibana

ufw allow 5601/tcp &&\

#configure Kibana

sudo bash -c 'echo server.port: 5601 >> /etc/kibana/kibana.yml &&\

#To allow connections from remote users, set this parameter to a non-loopback address.

sudo bash -c 'echo server.host: "IP.OF.ELK.SERVER" >> /etc/kibana/kibana.yml &&\

#Set the Elasticsearch URL

sudo bash -c 'echo elasticsearch.hosts: ["http://IP.OF.ELK.SERVER:9200"] >> /etc/kibana/kibana.yml &&\

#Configure Nginx with SSL to Proxy Kibana

#install Nginx

Install Nginx &&\

#Generate Self-signed SSL/TLS certificates

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana-selfsigned.key -out /etc/ssl/certs/kibana-selfsigned.crt &&\

#create Deffie-Hellman group.

openssl dhparam -out /etc/nginx/dhparam.pem 2048 &&\


#create and edit config file for Nginx

touch /etc/nginx/sites-available/kibana &&\

sudo bash -c 'echo 


server {
        listen 80;
        server_name my.ip.address.here;
        return 301 https://$host$request_uri;
}
server {
        listen 443 ssl;
        server_name elk.example.com;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;

        ssl_certificate /etc/ssl/certs/kibana-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/kibana-selfsigned.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on; 
        ssl_dhparam /etc/nginx/dhparam.pem;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
        ssl_ecdh_curve secp384r1;
        ssl_session_timeout  10m;
        ssl_session_cache shared:SSL:10m;
        resolver 192.168.42.129 8.8.8.8 valid=300s;
        resolver_timeout 5s; 
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        access_log  /var/log/nginx/kibana_access.log;
        error_log  /var/log/nginx/kibana_error.log;

        auth_basic "Authentication Required";
        auth_basic_user_file /etc/nginx/kibana.users;

        location / {
                proxy_pass http://localhost:5601;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }
}" >> /etc/nginx/sites-available/kibana

#Configure Nginx Authentication


printf "Admin:$(openssl passwd -crypt Password)\n" > /etc/nginx/kibana.users &&\


#enable Kibana Nginx configuration


ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/ &&\

nginx -t &&\

systemctl reload nginx &&\

#If UFW is running, allow Nginx connections, both HTTP and HTTPS.

ufw allow 'Nginx Full' &&\

#start Kibana

systemctl enable --now kibana &&\

#Installing Logstash 

#checks to see if Java is installed, if not it will install

dependency_check_deb() {
java -version
if [ $? -ne 0 ]
    then
# Installing Java 8 if it's not installed
        sudo apt-get install openjdk-8-jre-headless -y
# Checking if java installed is less than version 7. If yes, installing Java 7. As logstash & Elasticsearch require Java 7 or later.
    elif [ "`java -version 2> /tmp/version && awk '/version/ { gsub(/"/, "", $NF); print ( $NF < 1.8 ) ? "YES" : "NO" }' /tmp/version`" == "YES" ]
        then
            sudo apt-get install openjdk-8-jre-headless -y
fi
}

dependency_check_rpm() {
    java -version
    if [ $? -ne 0 ]
        then
#Installing Java 8 if it's not installed
            sudo yum install jre-1.8.0-openjdk -y
# Checking if java installed is less than version 7. If yes, installing Java 8. As logstash & Elasticsearch require Java 7 or later.
        elif [ "`java -version 2> /tmp/version && awk '/version/ { gsub(/"/, "", $NF); print ( $NF < 1.8 ) ? "YES" : "NO" }' /tmp/version`" == "YES" ]
            then
                sudo yum install jre-1.8.0-openjdk -y
    fi
} &&\


#installing logstash

apt install logstash &&\

#Configure Logstash Input plugin

touch /etc/logstash/conf.d/beats-input.conf &&\

sudo bash -c "echo input {
  beats {
    port => 5044
  }
}" >> /etc/logstash/conf.d/beats-input.conf &&\

#Configure Logstash Output

touch /etc/logstash/conf.d/elasticsearch-output.conf &&\

sudo bash -c "echo output {
   elasticsearch {
     hosts => ["localhost:9200"]
     manage_template => false
     index => "ssh_auth-%{+YYYY.MM}"
 }
}" >> /etc/logstash/conf.d/elasticsearch-output.conf &&\

#installs Xterm to open verification in new terminals 

apt install xterm &&\


#verifications are below

#verify connection to elastic search

xterm -e telnet 192.168.0.101 9200 &&\

xterm -e filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"] &&\

#verify Elastic search data reception


xterm -e curl -X GET localhost:9200/_cat/indices?v &&\

#Check ssh_auth-2019.05 index;

xterm -e curl -X GET localhost:9200/ssh_auth-*/_search?pretty &&\

#to test if elastic search is working

xterm -e curl http://localhost:9200 &&\

#this commands tests logstash

xterm -e sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t &&\



echo please check all the verifications on the terminals that popup. If all is well everything is configured correctly


