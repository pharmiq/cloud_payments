# frozen_string_literal: true
module CloudPayments
  module Namespaces
    class Token < Base
      def topup(attributes, request_id: nil)
        cert = OpenSSL::X509::Certificate.new(client.config.x509_cert)
        pkey = OpenSSL::PKey::EC.new(client.config.ec_private_key)
        payload = client.config.serializer.dump(attributes)
        signature = OpenSSL::PKCS7.sign(cert, pkey, payload, [], OpenSSL::PKCS7::DETACHED)

        # Remove header, footer and "\n" symbols
        #
        signature_lines = signature.to_pem.lines
        formatted_signature = signature_lines[1, signature_lines.count - 2].map { |l| l.chomp }.join

        headers = { 'X-Signature' => formatted_signature }
        headers['X-Request-ID'] = request_id if request_id
        response = request(:topup, attributes, headers)

        Transaction.new(response[:model])
      end
    end
  end
end
