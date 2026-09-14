# frozen_string_literal: true

# Minimal valid Ruby fixture; all catalog rows are declared as infra skips.
module Oracle
  module InfraBoundary
    def self.declared?
      true
    end
  end
end
