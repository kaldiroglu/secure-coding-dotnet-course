using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public sealed class ListLoggerProvider : ILoggerProvider
{
    public readonly ConcurrentQueue<string> Messages = new();
    public ILogger CreateLogger(string categoryName) => new ListLogger(Messages);
    public void Dispose() { }

    private sealed class ListLogger(ConcurrentQueue<string> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => sink.Enqueue(formatter(state, exception));
    }
}
