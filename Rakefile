# frozen_string_literal: true

require 'steep/rake_task'
require 'rspec/core/rake_task'

namespace :test do
  # Task to run unit tests
  RSpec::Core::RakeTask.new(:unit) do |t|
    t.pattern = FileList['spec/*/**/*_spec.rb']
  end

  # Task to run type-checking tests
  Steep::RakeTask.new(:steep) do |t|
    t.check.severity_level = :error
    t.watch.verbose
  end
end
