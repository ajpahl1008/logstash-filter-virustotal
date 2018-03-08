require "logstash/filters/base"
require "logstash/namespace"
require "virustotal_api"


class LogStash::Filters::VirusTotal < LogStash::Filters::Base

  config_name "virustotal"
  config :apikey, :validate => :string, :default => ""
  config :wait_time, :validate => :number, :default => 0.5


  public
  def register

  end

  public
  def filter(event)

    if !event.get("target_url").nil?
       target_url =  event.get("target_url")
       puts "Conducting VirusTotal Analysis on URL: #{target_url}"
       @logger.debug? && @logger.debug("Conducting VirusTotal Analysis on Field: #{target_url}")

        vturl_report = VirustotalAPI::URLReport.find(target_url, apikey)

        # Wait for results
        until vturl_report.exists? do
         sleep(wait_time)
        end

        # URL for Report (if it exists)
        event.set("report_url", vturl_report.report_url);

        @logger.debug? && @logger.debug(puts vturl_report.report_url)

        # Report results
        #event.set(vturl_report.report["scans"]["Opera"])
        event.set("report_data", vturl_report.report )

    else
      puts "logstash-filter-virustotal: WARNING: target_url does not exist in event"
    end

    filter_matched(event)
  end
end
