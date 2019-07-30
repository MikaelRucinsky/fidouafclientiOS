Pod::Spec.new do |s|

  s.name         = "FidoUafClientiOS"
  s.version      = "0.1.5"
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
  s.ios.resource_bundle = { "io.hanko.FidoUafClientiOS" => "FidoUafClientiOS/**/*.{strings}" }
  s.public_header_files = "FidoUafClientiOS/**/*.h"

end
