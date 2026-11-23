def initialize; end
def self.initialize; end
def normal; end # trailing
def undecorated; end
# before only
def normal_b; end
class Sample
  def initialize(x); end
  def self.initialize; end
  def custom.initialize; end
  private def wrapped; end # trailing
  def first; end; def second; end # trailing
  def a; end; puts '# string'
  def b; end; puts 5 # trailing
  def nested
    def child; end # trailing
  end
  def postfix; end if true # trailing
  '💎'; def unicode; end
end
