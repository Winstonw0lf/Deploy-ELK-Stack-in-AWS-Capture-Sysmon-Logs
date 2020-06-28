Remove-Item 'C:\PAth\to\winlogbeat\config\file\winlogbeat.yml'

New-Item -Path "C:\PAth\to\winlogbeat\config\file" . -Name winlogbeat.yml


$config = @" 

setup.kibana:

winlogbeat.event_logs:
- name: Microsoft-Windows-Sysmon/Operational
    processors:
      - script:
          lang: javascript
          id: sysmon
          file: ${path.home}/module/sysmon/config/winlogbeat-sysmon.js

 - name: Security
    processors:
      - script:
          lang: javascript
          id: security
          file: ${path.home}/module/security/config/winlogbeat-security.js

output.elasticsearch:
  hosts:
    - 10.0.2.15:9200

logging.to_files: true

logging.files:
  path: C:\ProgramData\winlogbeat\Logs

logging.level: info

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

"@
Out_file -InputObject $config -Path c:/Path/top/winlogbeat.yml