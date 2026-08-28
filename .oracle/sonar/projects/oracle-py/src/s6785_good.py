Schema = object
Query = object
QueryDepthLimiter = object

schema = Schema(
    query=Query,
    extensions=[QueryDepthLimiter(max_depth=10)],
)
