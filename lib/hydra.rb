require 'hydra/trace'
require 'hydra/pipe'
require 'hydra/ssh'
require 'hydra/stdio'
require 'hydra/message'
require 'hydra/safe_fork'
require 'hydra/runner'
require 'hydra/worker'
require 'hydra/master'
require 'hydra/sync'
require 'hydra/remote_command'
require 'hydra/listener/abstract'
require 'hydra/listener/minimal_output'
require 'hydra/listener/report_generator'
require 'hydra/listener/notifier'
require 'hydra/listener/progress_bar'
require 'hydra/runner_listener/abstract'
require 'monitor'

require 'hydra/test_processor'
require 'hydra/test_processor/spec'
require 'hydra/test_processor/cucumber'

module Hydra
  WRITE_LOCK = Monitor.new
  
  def load_config(config_file)
    begin
      config_erb = ERB.new(IO.read(config_file)).result(binding)
    rescue Exception => e
      raise(YmlLoadError,"config file was found, but could not be parsed with ERB.\n#{$!.inspect}")
    end

    begin
      config_yml = YAML::load(config_erb)
    rescue StandardError => e
      raise(YmlLoadError,"config file was found, but could not be parsed.\n#{$!.inspect}")
    end
    config_yml.stringify_keys
  end
  
  extend self
end
