import React, {useState, useEffect} from 'react';
import clsx from 'clsx';

function transformImgClassName(className) {
  return clsx(className, 'zoomableImg');
}

export default function MDXImg(props) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    const {overflow} = document.body.style;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = overflow;
    };
  }, [open]);

  return (
    <>
      {/* eslint-disable-next-line jsx-a11y/alt-text, jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/click-events-have-key-events */}
      <img
        decoding="async"
        loading="lazy"
        {...props}
        className={transformImgClassName(props.className)}
        onClick={() => setOpen(true)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') setOpen(true);
        }}
      />
      {open && (
        // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
        <div
          className="imgLightboxOverlay"
          role="dialog"
          aria-modal="true"
          aria-label={props.alt || 'Enlarged image'}
          onClick={() => setOpen(false)}>
          <img src={props.src} alt={props.alt} className="imgLightboxImage" />
          <button
            type="button"
            className="imgLightboxClose"
            aria-label="Close"
            onClick={() => setOpen(false)}>
            ×
          </button>
        </div>
      )}
    </>
  );
}
