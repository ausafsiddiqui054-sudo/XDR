namespace Hasinix.Web.Components.Shared;

public enum RiskAcceptanceDialogMode
{
    Request,
    Approve,
    Reject
}

/// <summary>What <see cref="FindingOwnerDialog"/> returns. Both null clears the owner and due date.</summary>
public sealed record FindingOwnerChoice(string? Owner, DateOnly? DueDate);

/// <summary>What <see cref="RiskAcceptanceDialog"/> returns: the reason or note, and the end date when requesting.</summary>
public sealed record RiskAcceptanceChoice(string Text, DateOnly? Until);
