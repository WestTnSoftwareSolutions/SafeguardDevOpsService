import { Component, OnInit } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { finalize } from 'rxjs/operators';
import { DevOpsServiceClient } from '../service-client.service';

@Component({
  selector: 'app-edit-a2a-ip-restrictions',
  templateUrl: './edit-a2a-ip-restrictions.component.html',
  styleUrls: ['./edit-a2a-ip-restrictions.component.scss']
})
export class EditA2AIpRestrictionsComponent implements OnInit {
  mode = 'AutoDetect';
  restrictionsText = '';
  effectiveRestrictions: string[] = [];
  confirmUnrestricted = false;
  reconciliationStatus: string;
  updatedAccountCount = 0;
  failures: any[] = [];
  isLoading = true;
  error = null;

  constructor(
    private serviceClient: DevOpsServiceClient,
    private dialogRef: MatDialogRef<EditA2AIpRestrictionsComponent>,
    private snackbar: MatSnackBar) { }

  ngOnInit(): void {
    this.serviceClient.getA2AIpRestrictions()
      .pipe(finalize(() => this.isLoading = false))
      .subscribe({
        next: settings => this.applySettings(settings),
        error: error => this.error = error
      });
  }

  private applySettings(settings: any): void {
    this.mode = settings?.Mode ?? 'AutoDetect';
    this.restrictionsText = (settings?.IpRestrictions ?? []).join('\n');
    this.effectiveRestrictions = settings?.EffectiveIpRestrictions ?? [];
    this.reconciliationStatus = settings?.ReconciliationStatus;
    this.updatedAccountCount = settings?.UpdatedAccountCount ?? 0;
    this.failures = settings?.Failures ?? [];
  }

  save(): void {
    this.error = null;
    this.failures = [];
    this.isLoading = true;
    const restrictions = this.restrictionsText.split(/[\r\n,]+/)
      .map(value => value.trim()).filter(value => value.length > 0);
    this.serviceClient.putA2AIpRestrictions({
      Mode: this.mode,
      IpRestrictions: restrictions,
      ConfirmUnrestricted: this.mode === 'Unrestricted' && this.confirmUnrestricted
    }).pipe(finalize(() => this.isLoading = false))
      .subscribe({
        next: settings => {
          this.applySettings(settings);
          if (settings.ReconciliationStatus === 'PartialFailure') {
            this.error = { message: 'The policy was saved, but one or more Safeguard accounts could not be updated.' };
          } else {
            this.snackbar.open('A2A IP restrictions updated.', 'Dismiss', { duration: 5000 });
            this.dialogRef.close(true);
          }
        },
        error: error => this.error = error
      });
  }

  close(): void {
    this.dialogRef.close(false);
  }

  get canSave(): boolean {
    if (this.isLoading)
      return false;
    if (this.mode === 'Explicit' && this.restrictionsText.trim().length === 0)
      return false;
    return this.mode !== 'Unrestricted' || this.confirmUnrestricted;
  }
}
