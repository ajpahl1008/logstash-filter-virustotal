# logstash-filter-virustotal (beta)
Connects to VirusTotal API services for URL information.

# Prerequisites
git, ruby

# Download & Compile
```
# git clone http://github.com/ajpahl1008/logstash-filter-virustotal.github
# cd logstash-filter-virustotal
# gem clean; gem build logstash-filter-virustotal.gemspec
```
This will create logstash-filter-virustotal-6.1.1.gem

# Installation
```
cd ${LOGSTASH_DIR}
bin/logstash-plugin install ${PATH_TO_GEM}
```

# Example Default Logstash Config
In this example, the sentiment defaults to the message field in the event.
```
input {...}

filter {
  virustotal { 
        apikey=>"YOURAPIKEY"
        url_field_name => "target_url" // Configurable field that contains the url.
        wait_on_vt => 10               // Sets a Timeout waiting for a response (seconds)
   }
}

output {...}
```

# Example output (running in debug)
Starting logstash (with plugin installed) in debug mode
```
bin/logstash -e 'input { stdin{codec => json_lines} } filter { sentiment { apikey => "YOURAPIKEY"} } output {stdout { codec => rubydebug }}'
```
Manually enter a JSON Doc: {"target_url":"http://www.cnn.com"} (Hit enter)
```
{
     { "target_url" : "http://www.dropbox.com" }            
     Conducting VirusTotal Analysis on URL: http://www.dropbox.com
     {
                "host" => "logstash-server.local",
         "report_data" => {
                   "scan_id" => "e25d4b397c5a0a51d506f44f2a7c727cc5564cc69cdf74c908c197cb86cdf349-1520473522",
             "response_code" => 1,
               "filescan_id" => nil,
                     "scans" => {
                           "MalwareDomainList" => {
                     "detected" => false,
                       "result" => "clean site",
                       "detail" => "http://www.malwaredomainlist.com/mdl.php?search=www.dropbox.com"
                 },
                                    "CLEAN MX" => {
                     "detected" => false,
                       "result" => "clean site"
                 },
                                    "Emsisoft" => {
                     "detected" => false,
                       "result" => "clean site"
                 },
                            "Malc0de Database" => {
                     "detected" => false,
                       "result" => "clean site",
                       "detail" => "http://malc0de.com/database/index.php?search=www.dropbox.com"
                 
                         "Google Safebrowsing" => {
                     "detected" => false,
                       "result" => "clean site"
                 },
                   ABBREVIATED SAMPLE
             },
               "verbose_msg" => "Scan finished, scan information embedded in this object",
                 "scan_date" => "2018-03-08 01:45:22",
                     "total" => 67,
                 "permalink" => "https://www.virustotal.com/url/e25d4b397c5a0a51d506f44f2a7c727cc5564cc69cdf74c908c197cb86cdf349/analysis/1520473522/",
                  "resource" => "http://www.dropbox.com",
                 "positives" => 0,
                       "url" => "http://www.dropbox.com/"
         },
          "@timestamp" => 2018-03-08T13:32:40.583Z,
          "target_url" => "http://www.dropbox.com",
            "@version" => "1",
          "report_url" => "https://www.virustotal.com/url/e25d4b397c5a0a51d506f44f2a7c727cc5564cc69cdf74c908c197cb86cdf349/analysis/1520473522/"
     }

}

```

Try entering a blank doc: { } (Hit enter)
```
logstash-filter-virustotal: WARNING: target_url does not exist in event
{
      "@version" => "1",
          "host" => "mylaptop.local",
    "@timestamp" => 2018-01-21T19:24:40.230Z
}
```
