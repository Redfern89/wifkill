# Если ssh-agent не запущен – запускаем
if ! pgrep -u "$USER" ssh-agent > /dev/null; then
    eval "$(ssh-agent -s)" > /dev/null
fi

# Добавляем приватные ключи, если они ещё не добавлены
find ~/.ssh/ -maxdepth 1 -name 'id_rsa_*' ! -name '*.pub' | while IFS= read -r key; do
    ssh-add -l | grep -q "$(ssh-keygen -lf "$key" | awk '{print $2}')" || ssh-add "$key"
done