Pod::Spec.new do |s|

  s.name         = "FidoUafClientiOS"
  s.version      = "1.0.0"
  s.summary      = "A FIDO UAF Client for iOS."
  s.description  = <<-DESC
  A FIDO Client for iOS which implements the UAF specification.
                   DESC
  s.homepage     = "https://github.com/teamhanko/fidouafclientiOS"

  s.license      = "Apache License, Version 2.0"

  s.author             = "Hanko GmbH"

  s.platform     = :ios, "10.0"

  s.source       = { :git => "https://github.com/teamhanko/fidouafclientiOS.git", :tag => "#{s.version}" }

  s.source_files  = "FidoUafClientiOS/**/*.{h,m,swift}"
  s.resource_bundles = { 
    'io_hanko_fidouafclientios' => [ 'FidoUafClientiOS/**/*.{strings}' ]
  }
  s.public_header_files = "FidoUafClientiOS/**/*.h"

end
