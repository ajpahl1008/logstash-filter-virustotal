# encoding: utf-8
require 'spec_helper'
require "logstash/filters/virustotal"

describe LogStash::Filters::VirusTotal do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        virustotal {
          url => "http://www.mtv.com"
        }
      }
    CONFIG
    end

    sample("url" => "fail") do
      expect(subject.get("url")).to eq('PASS')
    end
  end
end
