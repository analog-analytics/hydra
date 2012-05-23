# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{hydra}
  s.version = "0.23.3.24"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Nick Gauthier"]
  s.date = %q{2010-11-03}
  s.description = %q{Spread your tests over multiple machines to test your code faster.}
  s.email = %q{nick@smartlogicsolutions.com}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc",
     "TODO"
  ]
  s.files = [
    ".document",
     ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "TODO",
     "VERSION",
     "caliper.yml",
     "hydra-icon-64x64.png",
     "hydra.gemspec",
     "hydra_gray.png",
     "lib/hydra.rb",
     "lib/hydra/cucumber/formatter.rb",
     "lib/hydra/hash.rb",
     "lib/hydra/js/lint.js",
     "lib/hydra/listener/abstract.rb",
     "lib/hydra/listener/minimal_output.rb",
     "lib/hydra/listener/notifier.rb",
     "lib/hydra/listener/progress_bar.rb",
     "lib/hydra/listener/report_generator.rb",
     "lib/hydra/master.rb",
     "lib/hydra/message.rb",
     "lib/hydra/message/master_messages.rb",
     "lib/hydra/message/runner_messages.rb",
     "lib/hydra/message/worker_messages.rb",
     "lib/hydra/messaging_io.rb",
     "lib/hydra/pipe.rb",
     "lib/hydra/runner.rb",
     "lib/hydra/safe_fork.rb",
     "lib/hydra/spec/autorun_override.rb",
     "lib/hydra/spec/hydra_formatter.rb",
     "lib/hydra/ssh.rb",
     "lib/hydra/stdio.rb",
     "lib/hydra/sync.rb",
     "lib/hydra/tasks.rb",
     "lib/hydra/tmpdir.rb",
     "lib/hydra/trace.rb",
     "lib/hydra/worker.rb",
     "test/fixtures/assert_true.rb",
     "test/fixtures/config.yml",
     "test/fixtures/conflicting.rb",
     "test/fixtures/features/step_definitions.rb",
     "test/fixtures/features/write_alternate_file.feature",
     "test/fixtures/features/write_file.feature",
     "test/fixtures/hello_world.rb",
     "test/fixtures/js_file.js",
     "test/fixtures/json_data.json",
     "test/fixtures/slow.rb",
     "test/fixtures/sync_test.rb",
     "test/fixtures/write_file.rb",
     "test/fixtures/write_file_alternate_spec.rb",
     "test/fixtures/write_file_spec.rb",
     "test/fixtures/write_file_with_pending_spec.rb",
     "test/master_test.rb",
     "test/message_test.rb",
     "test/pipe_test.rb",
     "test/runner_test.rb",
     "test/ssh_test.rb",
     "test/sync_test.rb",
     "test/test_helper.rb",
     "test/worker_test.rb"
  ]
  s.homepage = %q{http://github.com/ngauthier/hydra}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{Distributed testing toolkit}
  s.test_files = [
    "test/pipe_test.rb",
     "test/sync_test.rb",
     "test/ssh_test.rb",
     "test/fixtures/write_file_alternate_spec.rb",
     "test/fixtures/sync_test.rb",
     "test/fixtures/hello_world.rb",
     "test/fixtures/features/step_definitions.rb",
     "test/fixtures/assert_true.rb",
     "test/fixtures/slow.rb",
     "test/fixtures/write_file_spec.rb",
     "test/fixtures/conflicting.rb",
     "test/fixtures/write_file_with_pending_spec.rb",
     "test/fixtures/write_file.rb",
     "test/message_test.rb",
     "test/test_helper.rb",
     "test/master_test.rb",
     "test/runner_test.rb",
     "test/worker_test.rb"
  ]

  s.add_dependency(%q<SystemTimer>)
  s.add_dependency(%q<SyslogLogger>, ["= 1.4.0"])

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<shoulda>, ["= 2.10.3"])
      s.add_development_dependency(%q<rspec>, ["= 2.0.0.beta.19"])
      s.add_development_dependency(%q<cucumber>, ["= 0.9.2"])
      s.add_development_dependency(%q<therubyracer>, ["= 0.7.4"])
    else
      s.add_dependency(%q<shoulda>, ["= 2.10.3"])
      s.add_dependency(%q<rspec>, ["= 2.0.0.beta.19"])
      s.add_dependency(%q<cucumber>, ["= 0.9.2"])
      s.add_dependency(%q<therubyracer>, ["= 0.7.4"])
    end
  else
    s.add_dependency(%q<shoulda>, ["= 2.10.3"])
    s.add_dependency(%q<rspec>, ["= 2.0.0.beta.19"])
    s.add_dependency(%q<cucumber>, ["= 0.9.2"])
    s.add_dependency(%q<therubyracer>, ["= 0.7.4"])
  end
end

