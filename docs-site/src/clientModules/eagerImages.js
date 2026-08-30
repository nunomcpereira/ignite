// Docusaurus's MDX <img> component auto-sets loading="lazy" on every doc
// image. Combined with docusaurus-plugin-image-zoom (medium-zoom), which
// attaches to every `.markdown img` ~1s after mount, native lazy-loading's
// intersection observer never fires for images already in the viewport at
// that point - the <img> just sits at complete:false/naturalWidth:0
// forever, rendering as an empty box. Forcing eager loading sidesteps the
// interaction entirely; these are a handful of already-compressed
// screenshots per page, not a real perf concern to lazy-load.
function makeImagesEager() {
  document.querySelectorAll('img[loading="lazy"]').forEach((img) => {
    img.loading = 'eager';
  });
}

export function onRouteDidUpdate() {
  makeImagesEager();
}

if (typeof window !== 'undefined') {
  makeImagesEager();
  // MDX content mounts after this module's top-level code runs - one more
  // pass on the next tick catches images not yet in the DOM here.
  setTimeout(makeImagesEager, 0);
}
