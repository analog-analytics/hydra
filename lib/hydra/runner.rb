require 'test/unit'

begin
  # Ruby 1.8 Test::Unit
  require 'test/unit/testresult'
  Test::Unit.run = true
rescue LoadError
  # Ruby 1.9 Test::Unit
  class Test::Unit::Runner
    @@stop_auto_run = true
  end
end

require 'thread'
require 'timeout'
require 'tempfile'

module Hydra #:nodoc:
  # Hydra class responsible for running test files.
  #
  # The Runner is never run directly by a user. Runners are created by a
  # Worker to run test files.
  #
  # The general convention is to have one Runner for each logical processor
  # of a machine.
  class Runner
    include Hydra::Messages::Runner
    traceable('RUNNER')

    DEFAULT_LOG_FILE = File.join('log', 'hydra-runner.log')
    LOCK = Mutex.new

    # Boot up a runner. It takes an IO object (generally a pipe from its
    # parent) to send it messages on which files to execute.
    def initialize(opts = {})
      @verbose = opts.fetch(:verbose) { false }
      @runner_num = opts[:runner_num]
      @runner_log_file = opts[:runner_log_file]
      @runner_log_file = DEFAULT_LOG_FILE + @runner_num.to_s if ["", nil].include? @runner_log_file
      redirect_output( @runner_log_file )
      reg_trap_sighup

      @io = opts.fetch(:io) { raise "No IO Object" }
      @remote = opts.fetch(:remote) { false }      
      @event_listeners = Array( opts.fetch( :runner_listeners ) { nil } )

      $stdout.sync = true

      @test_opts = opts.fetch(:test_opts) { "" }
      @test_failure_guard_regexp = opts.fetch(:test_failure_guard_regexp) { "" }

      ENV['HYDRA_VERBOSE'] = "true" if @verbose

      trace 'Booted. Sending Request for file'
      
      ENV["TEST_DB_ID"] = "#{ENV["USER"]}#{@runner_num}"
      runner_begin

      trace 'Booted. Sending Request for file'
      @io.write RequestFile.new
      begin
        process_messages
      rescue => ex
        trace "Caught exception while processing messages: #{ex.inspect}\n#{ex.backtrace}"
        raise ex
      end
    end
    
    def run_shell_command(cmd, msg)
      result = `#{cmd}`
      status = $?
      trace_msg = "#{msg} env: #{ENV['RAILS_ENV']} #{ENV['TEST_ENV_NUMBER']} (exited: #{status.inspect}) -> #{result}"
      trace trace_msg
      raise "Error running #{cmd} #{trace_msg}" unless status.success?
    end

    def reg_trap_sighup
      for sign in [:SIGHUP, :INT]
        trap sign do
          stop
        end
      end
      @runner_began = true
    end

    def runner_begin
      trace "Firing runner_begin event"
      @event_listeners.each {|l| l.runner_begin( self ) }
    end

    def reg_trap_sighup
      for sign in [:SIGHUP, :INT]
        trap sign do
          stop
        end
      end
      @runner_began = true
    end

    def runner_begin
      trace "Firing runner_begin event"
      @event_listeners.each {|l| l.runner_begin( self ) }
    end

    # Run a test file and report the results
    def run_file(file)
      trace "Running file: #{file}"

      output = ""
      if file =~ /_spec.rb$/i || file =~ /spec\/? -e/i
        output = run_rspec_file(file)
      elsif file =~ /.feature$/i
        output = run_cucumber_file(file)
      elsif file =~ /.js$/i or file =~ /.json$/i
        output = run_javascript_file(file)
      else
        output = run_test_unit_file(file)
      end

      output = "." if output == ""

      @io.write Results.new(:output => output, :file => file)
      return output
    end

    # Stop running
    def stop
      runner_end if @runner_began
      @runner_began = @running = false
      trace "About to close my io"
      @io.close
      trace "io closed"
    end

    def runner_end
      trace "Ending runner #{self.inspect}"
      @event_listeners.each {|l| l.runner_end( self ) }
    end

    def format_exception(ex)
      "#{ex.class.name}: #{ex.message}\n    #{ex.backtrace.join("\n    ")}"
    end

    private

    # The runner will continually read messages and handle them.
    def process_messages
      trace "Processing Messages"
      @running = true
      while @running
        begin
          message = @io.gets
          if message and !message.class.to_s.index("Worker").nil?
            trace "Received message from worker"
            trace "\t#{message.inspect}"
            message.handle(self)
          else
            @io.write Ping.new
          end
        rescue IOError
          trace "Runner lost Worker"
          stop
        end
      end
      trace "Stopped Processing Messages"
    end

    def format_ex_in_file(file, ex)
      "Error in #{file}:\n  #{format_exception(ex)}"
    end

    # Run all the Test::Unit Suites in a ruby file
    def run_test_unit_file(file)
      begin
        require file
      rescue LoadError => ex
        trace "#{file} does not exist [#{ex.to_s}]"
        return ex.to_s
      rescue Exception => ex
        trace "Error requiring #{file} [#{ex.to_s}]"
        return format_ex_in_file(file, ex)
      end
      output = []

      if defined?(Test::Unit::TestResult)
        @result = Test::Unit::TestResult.new
        @result.add_listener(Test::Unit::TestResult::FAULT) do |value|
          output << value
        end
      end

      klasses = Runner.find_classes_in_file(file)
      begin
        if defined?(Test::Unit::Runner)
          runner = Test::Unit::Runner.new
          klasses.each do |suite|
            suite.test_methods.each do |test_method|
              inst = suite.new(test_method)
              inst.run(runner)
            end
          end

          unless runner.report.empty?
            output += runner.report
          end
        else
          klasses.each do |klass|
            klass.suite.run(@result){|status, name| ;}
          end
        end
      rescue => ex
        output << format_ex_in_file(file, ex)
      end

      return output.join("\n")
    end

    # run all the Specs in an RSpec file (NOT IMPLEMENTED)
    def run_rspec_file(file)
      trace "about to process spec file: #{file}"
      Hydra::TestProcessor::Spec.new(file,
                                     :verbose => @verbose,
                                     :runner_num => @runner_num,
                                     :test_opts => @test_opts,
                                     :test_failure_guard_regexp => @test_failure_guard_regexp).process!
    end

    # run all the scenarios in a cucumber feature file
    def run_cucumber_file(file)
      Hydra::TestProcessor::Cucumber.new(file,
                                     :verbose => @verbose,
                                     :runner_num => @runner_num,
                                     :test_opts => @test_opts,
                                     :test_failure_guard_regexp => @test_failure_guard_regexp).process!
    end

    def run_javascript_file(file)
      errors = []
      require 'v8'
      V8::Context.new do |context|
        context.load(File.expand_path(File.join(File.dirname(__FILE__), 'js', 'lint.js')))
        context['input'] = lambda{
          File.read(file)
        }
        context['reportErrors'] = lambda{|js_errors|
          js_errors.each do |e|
            e = V8::To.rb(e)
            errors << "\n\e[1;31mJSLINT: #{file}\e[0m"
            errors << "  Error at line #{e['line'].to_i + 1} " + 
              "character #{e['character'].to_i + 1}: \e[1;33m#{e['reason']}\e[0m"
            errors << "#{e['evidence']}"
          end
        }
        context.eval %{
          JSLINT(input(), {
            sub: true,
            onevar: true,
            eqeqeq: true,
            plusplus: true,
            bitwise: true,
            regexp: true,
            newcap: true,
            immed: true,
            strict: true,
            rhino: true
          });
          reportErrors(JSLINT.errors);
        }
      end

      if errors.empty?
        return '.'
      else
        return errors.join("\n")
      end
    end

    # find all the test unit classes in a given file, so we can run their suites
    def self.find_classes_in_file(f)
      code = ""
      File.open(f) {|buffer| code = buffer.read}
      matches = code.scan(/class\s+([\S]+)/)
      klasses = matches.collect do |c|
        begin
          if c.first.respond_to? :constantize
            c.first.constantize
          else
            eval(c.first)
          end
        rescue NameError
          # means we could not load [c.first], but thats ok, its just not
          # one of the classes we want to test
          nil
        rescue SyntaxError
          # see above
          nil
        end
      end

      return klasses.select do |klass|
        klass && (klass.respond_to?(:suite) || klass.ancestors.include?(Test::Unit::TestCase))
      end
    end

    # Yanked a method from Cucumber
    def tag_excess(features, limits)
      limits.map do |tag_name, tag_limit|
        tag_locations = features.tag_locations(tag_name)
        if tag_limit && (tag_locations.length > tag_limit)
          [tag_name, tag_limit, tag_locations]
        else
          nil
        end
      end.compact
    end

    def redirect_output file_name
      file = nil
      file_flags = @verbose ? "a" : "w"
      begin
        file = File.open(file_name, file_flags)
      rescue
        # it should always redirect output in order to handle unexpected interruption
        # successfully
        file = File.open(DEFAULT_LOG_FILE, file_flags)
      end
      $stdout.reopen(file)
      $stderr.reopen(file)
      $stdout.sync = true
      $stderr.sync = true
      trace "redirected output to: #{file.path}"
    end
  end
end

