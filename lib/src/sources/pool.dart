Future<List<R>> mapPool<T, R>(
    List<T> items, int concurrency, Future<R> Function(T) action) async {
  final results = List<R?>.filled(items.length, null);
  var next = 0;
  Future<void> worker() async {
    while (next < items.length) {
      final i = next++;
      results[i] = await action(items[i]);
    }
  }

  await Future.wait(
      [for (var i = 0; i < concurrency && i < items.length; i++) worker()]);
  return results.cast<R>();
}
