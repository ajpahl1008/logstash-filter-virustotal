require "logstash/filters/base"
require "logstash/namespace"
require "virustotal_api"


class LogStash::Filters::VirusTotal < LogStash::Filters::Base

  config_name "virustotal"
  config :apikey, :validate => :string, :default => ""
  config :wait_time, :validate => :number, :default => 0.5
  config :wait_on_vt, :validate => :number, :default => 5
  config :url_field_name, :validate => :string, :default => "url"

  public
  def register

  end

  public
  def filter(event)

    if !event.get(url_field_name).nil?
       target_url =  event.get(url_field_name)
       puts "Conducting VirusTotal Analysis on URL: #{target_url}"
       @logger.debug? && @logger.debug("Conducting VirusTotal Analysis on Specificed URL Field: #{target_url}")

       vturl_report = VirustotalAPI::URLReport.find(target_url, apikey)

       bust_out = false
       total_wait_time = 0

        # Wait for results
        until vturl_report.exists? or bust_out == true do
         sleep(wait_time)
         total_wait_time += wait_time
         if total_wait_time > wait_on_vt
           bust_out = true
           puts "Timeout waiting for VT response"
         end
        end

        # URL for Report (if it exists)
        event.set("report_url", vturl_report.report_url);

        @logger.debug? && @logger.debug(puts vturl_report.report_url)

        # Report results
        event.set("report_data", vturl_report.report )

    else
      puts "logstash-filter-virustotal: WARNING: target_url does not exist in event"
    end

    filter_matched(event)
  end
end
