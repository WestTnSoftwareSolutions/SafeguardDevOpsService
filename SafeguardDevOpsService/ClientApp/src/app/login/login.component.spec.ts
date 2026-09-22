import { of } from 'rxjs';

import { LoginComponent } from './login.component';

describe('LoginComponent', () => {
  let storage: { [key: string]: string };
  let windowMock: any;
  let client: any;
  let authService: any;

  beforeEach(() => {
    storage = {};
    windowMock = {
      sessionStorage: {
        getItem: (key: string) => storage[key] ?? null,
        setItem: (key: string, value: string) => storage[key] = value,
        removeItem: (key: string) => delete storage[key]
      },
      location: { reload: jasmine.createSpy('reload') }
    };
    client = { getSafeguard: jasmine.createSpy('getSafeguard') };
    authService = { login: jasmine.createSpy('login') };
  });

  it('uses the effective system trust value returned by the service', () => {
    client.getSafeguard.and.returnValue(of({ TrustSystemStore: false }));
    const component = new LoginComponent(client, windowMock, authService);

    component.ngOnInit();

    expect(component.trustSystemStore).toBeFalse();
  });

  it('preserves the appliance address and trust choice across the Safeguard redirect', () => {
    client.getSafeguard.and.returnValue(of({ TrustSystemStore: true }));
    const component = new LoginComponent(client, windowMock, authService);
    component.applianceAddress = 'spp.example.com';
    component.trustSystemStore = true;

    component.connect();

    expect(storage.ApplianceAddress).toBe('spp.example.com');
    expect(storage.TrustSystemStore).toBe('true');
    expect(authService.login).toHaveBeenCalledWith('spp.example.com');
  });
});
