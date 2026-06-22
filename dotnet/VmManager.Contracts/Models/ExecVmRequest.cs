using System.ComponentModel.DataAnnotations;

namespace VmManager.Contracts.Models;

/// <summary>
/// Request body for POST /api/vms/{name}/exec.
/// Executes a PowerShell script inside a VM via WinRM.
/// </summary>
public class ExecVmRequest
{
    /// <summary>PowerShell script to execute inside the VM.</summary>
    [Required]
    public string Script { get; set; } = "";

    /// <summary>Execution timeout in seconds (default: 60, max: 600).</summary>
    [Range(1, 600)]
    public int Timeout { get; set; } = 60;
}
