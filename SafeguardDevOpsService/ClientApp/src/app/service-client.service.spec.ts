import { of } from 'rxjs';

import { DevOpsServiceClient } from './service-client.service';

describe('DevOpsServiceClient', () => {
  function createClient(): { client: DevOpsServiceClient, http: any } {
    const http = {
      put: jasmine.createSpy('put').and.returnValue(of({}))
    };
    const windowMock = {
      sessionStorage: {
        getItem: (key: string) => key === 'UserToken' ? 'test-token' : null
      }
    };
    return {
      client: new DevOpsServiceClient(http as any, windowMock as any, {} as any),
      http
    };
  }

  it('uses verified TLS when system trust is selected during bootstrap', () => {
    const { client, http } = createClient();

    client.putSafeguardAppliance('spp.example.com', true).subscribe();

    expect(http.put).toHaveBeenCalledWith(
      '/service/devops/v2/Safeguard',
      {
        ApplianceAddress: 'spp.example.com',
        IgnoreSsl: false,
        TrustSystemStore: true
      },
      { headers: { Authorization: 'spp-token test-token' } });
  });

  it('retains the legacy insecure bootstrap when system trust is cleared', () => {
    const { client, http } = createClient();

    client.putSafeguardAppliance('spp.example.com', false).subscribe();

    expect(http.put.calls.mostRecent().args[1]).toEqual({
      ApplianceAddress: 'spp.example.com',
      IgnoreSsl: true,
      TrustSystemStore: false
    });
  });
});
