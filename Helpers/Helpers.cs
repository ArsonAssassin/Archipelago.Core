using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public static class Helpers
    {
        private static CancellationTokenSource _cancellationTokenSource { get; set; } = new CancellationTokenSource();
        private static readonly List<CancellationTokenSource> _linkedTokenSources = new();
        internal static CancellationToken CombineTokens(CancellationToken externalToken)
        {
            if (externalToken == default || externalToken == CancellationToken.None)
            {
                return _cancellationTokenSource.Token;
            }

            var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
                _cancellationTokenSource.Token,
                externalToken
            );

            lock (_linkedTokenSources)
            {
                // Dispose and remove sources whose cancellation has already been requested
                // to prevent unbounded growth of the list.
                var stale = _linkedTokenSources.Where(s => s.IsCancellationRequested).ToList();
                foreach (var src in stale)
                {
                    src.Dispose();
                    _linkedTokenSources.Remove(src);
                }
                _linkedTokenSources.Add(linkedSource);
            }

            return linkedSource.Token;
        }


    }
}
