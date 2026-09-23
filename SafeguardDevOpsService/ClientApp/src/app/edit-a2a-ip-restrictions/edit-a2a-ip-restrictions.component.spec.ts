import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatRadioModule } from '@angular/material/radio';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { of } from 'rxjs';
import { DevOpsServiceClient } from '../service-client.service';
import { EditA2AIpRestrictionsComponent } from './edit-a2a-ip-restrictions.component';

describe('EditA2AIpRestrictionsComponent', () => {
  let fixture: ComponentFixture<EditA2AIpRestrictionsComponent>;
  let component: EditA2AIpRestrictionsComponent;
  const client = jasmine.createSpyObj('DevOpsServiceClient', ['getA2AIpRestrictions', 'putA2AIpRestrictions']);

  beforeEach(async () => {
    client.getA2AIpRestrictions.and.returnValue(of({ Mode: 'AutoDetect', EffectiveIpRestrictions: ['10.0.0.1'] }));
    await TestBed.configureTestingModule({
      declarations: [EditA2AIpRestrictionsComponent],
      imports: [FormsModule, MatDialogModule, MatSnackBarModule, MatRadioModule, MatCheckboxModule,
        MatFormFieldModule, MatInputModule, MatIconModule, MatButtonModule, MatProgressSpinnerModule,
        NoopAnimationsModule],
      providers: [
        { provide: DevOpsServiceClient, useValue: client },
        { provide: MatDialogRef, useValue: { close: jasmine.createSpy('close') } }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    }).compileComponents();
    fixture = TestBed.createComponent(EditA2AIpRestrictionsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('requires explicit confirmation before unrestricted mode can be saved', () => {
    component.mode = 'Unrestricted';
    component.confirmUnrestricted = false;
    expect(component.canSave).toBe(false);
    component.confirmUnrestricted = true;
    expect(component.canSave).toBe(true);
  });
});
