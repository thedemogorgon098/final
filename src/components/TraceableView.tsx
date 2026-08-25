"use client";

import { useEffect, useState, type ReactNode } from "react";

interface TraceableViewProps {
  recipientLabel: string;
  messageId?: string;
  enabled?: boolean;
  children: ReactNode;
}

export default function TraceableView({
  recipientLabel,
  messageId,
  enabled = true,
  children,
}: TraceableViewProps) {
  const [focused, setFocused] = useState(true);
  const timestamp = new Date().toISOString().slice(0, 16).replace("T", " ");

  useEffect(() => {
    if (!enabled) return;
    const onFocus = () => setFocused(true);
    const onBlur = () => setFocused(false);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onBlur);
    };
  }, [enabled]);

  if (!enabled) return <>{children}</>;

  const watermarkText = [recipientLabel, messageId ? `#${messageId.slice(0, 8)}` : null, timestamp]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className={`traceable-view${focused ? "" : " traceable-blurred"}`}>
      <div
        className="traceable-watermark"
        aria-hidden="true"
        style={{
          backgroundImage: `repeating-linear-gradient(
            -30deg,
            transparent,
            transparent 80px,
            rgba(0,242,254,0.04) 80px,
            rgba(0,242,254,0.04) 81px
          )`,
        }}
      >
        {Array.from({ length: 12 }).map((_, i) => (
          <span key={i} className="watermark-tile">
            {watermarkText}
          </span>
        ))}
      </div>
      <div className="traceable-content">{children}</div>
      {!focused && (
        <div className="traceable-blur-overlay">
          <i className="fa-solid fa-eye-slash" />
          <p>Content hidden — return to this tab to view</p>
        </div>
      )}
    </div>
  );
}
