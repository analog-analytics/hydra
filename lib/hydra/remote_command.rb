module Hydra #:nodoc:
  # Run a command on a remote server via SSH. A lot like Capistrano.
  class RemoteCommand
    include Open3
  
    attr_reader :results

    # remote_command: run this on all remote Hydra serves from config/hydra.yml
    # success_text: look for this text as a sign of success
    # verbose: echo all the SSH output
    def initialize(remote_command, success_text, verbose = false)
      config = YAML.load_file(File.join('config', 'hydra.yml') )
      environment = config.fetch('environment') { 'test' }
      workers = config.fetch('workers') { [] }
      workers = workers.select{|w| w['type'] == 'ssh'}

      Thread.abort_on_exception = true
      @listeners = []
      @results = {}
      workers.each do |worker|
        @listeners << Thread.new do
          begin
            run_remote_command(worker, environment, remote_command, success_text, verbose)
          rescue 
            @results[worker] = "==== #{@name} failed for #{worker['connect']} ====\n#{$!.inspect}\n#{$!.backtrace.join("\n")}"
          end
        end
      end
      @listeners.each{|l| l.join}
    end

    def run_remote_command worker, environment, remote_command, success_text, verbose
      ssh_opts = worker.fetch('ssh_opts') { '' }
      writer, reader, error = popen3("ssh -tt #{ssh_opts} #{worker['connect']} ")
      writer.write("cd #{worker['directory']}\n")
      writer.write "echo BEGIN HYDRA\n"
      writer.write("#{remote_command}\n")
      $stdout.write("Run #{remote_command} on #{worker['connect']}\n") if verbose
      writer.write "echo END HYDRA\n"
      writer.write("exit\n")
      writer.close

      succeeded = false
      while line = reader.gets
        line.chomp!
        if verbose
          $stdout.write "#{worker['connect']}: #{line}\n"
        end
        if success_text.nil? || line[success_text]
          succeeded = true
        end
        @results[worker] = (@results[worker] || "") + "#{line}\n"
      end
    
      if !succeeded
        $stdout.write "Failed on #{worker['connect']}\n"
        $stdout.write @results[worker]
      end
    end
  end
end
