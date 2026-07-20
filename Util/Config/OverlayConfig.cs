using Archipelago.Core.Util.Overlay;

namespace Archipelago.Core.Util.Config
{
    public class OverlayConfig
    {
        public float XOffset { get; set; } = 100f;
        public float YOffset { get; set; } = 100f;
        public float FontSize { get; set; } = 14f;
        public float FadeDuration { get; set; } = 10.0f;
        public byte DefaultTextColorR { get; set; } = 255;
        public byte DefaultTextColorG { get; set; } = 255;
        public byte DefaultTextColorB { get; set; } = 255;
        public byte DefaultTextColorA { get; set; } = 255;

        /// <summary>
        /// Creates an OverlayOptions instance from this config section.
        /// </summary>
        public OverlayOptions ToOverlayOptions()
        {
            return new OverlayOptions
            {
                XOffset = XOffset,
                YOffset = YOffset,
                FontSize = FontSize,
                FadeDuration = FadeDuration,
                DefaultTextColor = new Color(
                    DefaultTextColorR, DefaultTextColorG,
                    DefaultTextColorB, DefaultTextColorA)
            };
        }
    }
}
