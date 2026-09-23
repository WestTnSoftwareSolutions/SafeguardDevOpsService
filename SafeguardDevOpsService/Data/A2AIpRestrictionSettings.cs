using System.Collections.Generic;

namespace OneIdentity.DevOps.Data
{
    /// <summary>
    /// Source IP policy applied to Safeguard A2A credential retrieval entries.
    /// </summary>
    public class A2AIpRestrictionSettings
    {
        /// <summary>
        /// AutoDetect, Explicit, or Unrestricted.
        /// </summary>
        public string Mode { get; set; }

        /// <summary>
        /// Configured IP addresses or CIDR ranges when Mode is Explicit.
        /// </summary>
        public string[] IpRestrictions { get; set; }

        /// <summary>
        /// Resolved restrictions that will be sent to Safeguard.
        /// </summary>
        public string[] EffectiveIpRestrictions { get; set; }

        /// <summary>
        /// Must be true when intentionally selecting Unrestricted mode.
        /// </summary>
        public bool ConfirmUnrestricted { get; set; }

        /// <summary>
        /// Succeeded, PartialFailure, or NotApplicable.
        /// </summary>
        public string ReconciliationStatus { get; set; }

        /// <summary>
        /// Number of existing retrievable accounts updated in Safeguard.
        /// </summary>
        public int UpdatedAccountCount { get; set; }

        /// <summary>
        /// Reconciliation failures, if any.
        /// </summary>
        public IList<A2AIpRestrictionFailure> Failures { get; set; } = new List<A2AIpRestrictionFailure>();
    }

    /// <summary>
    /// A failed A2A source IP reconciliation operation.
    /// </summary>
    public class A2AIpRestrictionFailure
    {
        /// <summary>The account or vault A2A registration.</summary>
        public string RegistrationType { get; set; }
        /// <summary>The affected Safeguard account, or null for a registration-wide failure.</summary>
        public int? AccountId { get; set; }
        /// <summary>The failure returned while applying the policy.</summary>
        public string Message { get; set; }
    }
}
