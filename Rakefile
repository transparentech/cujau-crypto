require 'rubygems'
Gem::manage_gems
require 'rake/gempackagetask'
require 'fileutils'

spec = Gem::Specification.new do |s| 
  s.name = "cujau.crypto"
  s.version = "0.0.1"
  s.author = "TransparenTech LLC"
  s.email = "nick@transparentech.com"
  s.homepage = "http://www.transparentech.com/"
  s.platform = Gem::Platform::RUBY
  s.summary = "Hybrid, asymmetric and symmetric cryptography library."
  s.require_path = "lib"
  #  s.autorequire = "crypto"

  # Don't set files and test_files here. Do it in the task below.
  # s.files = FileList["lib/**/*", "src/main/ruby/**/*"].to_a
  # s.test_files = FileList["tests/**/*test.rb"].to_a

  s.has_rdoc = true
  #  s.extra_rdoc_files = ["README"]
  #  s.add_dependency("dependency", ">= 0.x.x")
end
 

task :default do 
  # Build the temporary GEM directory structure and copy the required
  # files from the Maven structure.
  mkdir_p %w( target/gem/lib target/gem/pkg target/gem/tests )
  cp_r 'src/main/ruby/.', 'target/gem/lib'
  cp_r 'src/test/ruby/.', 'target/gem/tests'

  # Switch to the temporary GEM directory and add the files from there
  # to the Gem::Specification object.
  cd 'target/gem'
  spec.files = FileList["lib/**/*"].to_a
  spec.test_files = FileList["tests/**/*.rb"]
  
  # Define the GEM building task.
  Rake::GemPackageTask.new(spec) do |pkg| 
    pkg.need_tar = true 
    p pkg
  end
 
  p spec.files.inspect
  # Call the gem task.
  Rake::Task[:gem].invoke
  
  # Copy the GEM file into the toplevel target dir.
  cp_r 'pkg/.', '..'
end
