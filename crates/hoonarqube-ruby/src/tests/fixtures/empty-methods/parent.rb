class A
  def head; end # trailing
  def last; end # trailing
end
module B
  def last; end # trailing
end
def enclosing
  def a; end # trailing
  def last; end # trailing
end
if condition
  def a; end # trailing
  def last; end # trailing
end
def around
  1.times do
    def a; end # trailing
    def last; end # trailing
  end
end
class Holder
  start
  private def no_comment; end
  private def inside # comment
  end
  def with_body; 'end'; end # trailing
  def normal; end
  # after only
end
def top_last; end # trailing
