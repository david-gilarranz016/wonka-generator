# frozen_string_literal: true

require 'steep/rake_task'
require 'rspec/core/rake_task'
require 'rake/clean'
CLEAN = FileList['output/*']

namespace :test do
  # Task to run unit tests
  RSpec::Core::RakeTask.new(:unit) do |t|
    t.pattern = FileList['spec/generator/*_spec.rb']
  end

  # Task to run type-checking tests
  Steep::RakeTask.new(:steep) do |t|
    t.check.severity_level = :error
    t.watch.verbose
  end

  # Task to run API tests
  RSpec::Core::RakeTask.new(:api) do |t|
    ENV['APP_ENV'] = 'test'
    t.pattern = FileList['spec/api/*_spec.rb']

    # Clean up after tests
    at_exit { Rake::Task['clean'].execute }
  end
end
