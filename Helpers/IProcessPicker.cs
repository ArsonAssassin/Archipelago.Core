using Archipelago.Core.Models;
using System.Threading.Tasks;

namespace Archipelago.Core.Helpers
{
    public interface IProcessPicker
    {
        Task<ProcessInfo?> PickProcessAsync(string searchText);
    }
}
