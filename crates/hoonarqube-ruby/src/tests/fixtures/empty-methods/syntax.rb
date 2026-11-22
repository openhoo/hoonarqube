class Example
  def initialize
  end
  def self.initialize; end
  # Outside.
  def external; end # Outside.
  def header # explanatory
  end
  def multi(
    arg # parameter note
  )
  end
  def commented
    # implementation reason
  end
  def semis; ; ; end
  def semis_reason; ; # explained
  end
  '💎'; def self.ready; end # trailing
  private def hidden; end
  def [](key); end
  def value = nil
  def retryable
  rescue StandardError
  end
  def guarded
  ensure
  end
  def operation
    raise NotImplementedError
  end
  def blocky; -> {}; end
  def forwarded(...); end
  def param_default(x = 1); end
  def explicit_return; return; end
  def self.[]=(x,y); end
  def ==(other); end
end
