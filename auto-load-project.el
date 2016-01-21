(defun setup (dir)
  (find-file (concat dir "/project.clj"))
  )

(defun dismantle ()
  (kill-buffer "project.clj")
  )

(defun get-project-name (dir)
  (set-buffer "project.clj")
  (beginning-of-buffer)
  (re-search-forward " \\(.+\\) " nil t)
  (match-string 1)
  )

(defun underscore-name (name)
  (replace-regexp-in-string "-" "_" name))

(defun underscored-project-name (dir)
  (underscore-name (get-project-name dir)))

(defun lein-file-directory (dir part)
  (concat dir part "/" (underscored-project-name dir)))

(defun lein-file-location (dir type name)
  (concat  (lein-file-directory dir type) "/" name))


(defun auto-load-project ()
  (setq dir default-directory)

  (cider-jack-in)
  ;;   Need to figure out how to stop this opening as front buffer

  (setup dir)

  (split-window-horizontally)

  (find-file (lein-file-location dir "src" "core.clj"))
  (find-file-other-window (lein-file-location dir "test" "core_test.clj"))

  (other-window 1)

  (dismantle)
  )

(auto-load-project)
