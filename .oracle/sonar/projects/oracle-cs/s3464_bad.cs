class A<T>
{
}

class B<T> : A<B<B<T>>>
{
}

class C<T> : A<C<C<T>>>
{
}
